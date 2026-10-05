"""
Stage 13 hardened TCP/cryptographic backends with persistent audit logging.

The module keeps all blocking socket and cryptographic operations away from
Tkinter's main thread.  Each backend reports events through a callback supplied
by the GUI layer.

Security design:
- Alice generates an RSA-2048 key pair.
- Bob verifies Alice's public key and generates a random AES-256 session key.
- Bob protects the AES key using RSA-OAEP with SHA-256.
- Chat messages and file chunks use AES-256-GCM with fresh nonces.
- FILE transfers use SHA-256 for complete-file integrity verification.
- TCP packets use the existing length-prefixed NetworkProtocol module.
"""

from __future__ import annotations

import queue
import socket
import threading
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Optional

from crypto_manager import AESGCMEncryptedData, CryptoManager
from file_transfer import (
    EncryptedFileChunk,
    FileManifest,
    FileTransferManager,
    IncomingFileAssembler,
)
from network_protocol import (
    ConnectionClosedError,
    MessageType,
    NetworkProtocol,
    ProtocolError,
)
from logger_config import (
    configure_secure_logger,
    friendly_error_message,
    install_exception_hooks,
)

BackendCallback = Callable[[str, dict[str, Any]], None]


class BackendBase:
    """Shared socket, ACK-routing and callback services."""

    ACK_TIMEOUT_SECONDS = 30.0

    def __init__(self, callback: BackendCallback, role_name: str) -> None:
        self.callback = callback
        self.role_name = role_name
        self.logger, self.log_path = configure_secure_logger(role_name)
        install_exception_hooks(self.logger)
        self.send_lock = threading.Lock()
        self.lifecycle_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.disconnecting_event = threading.Event()
        self.receiver_thread: Optional[threading.Thread] = None
        self._ack_waiters: dict[str, queue.Queue[dict[str, Any]]] = {}
        self._ack_waiters_lock = threading.Lock()

    def emit(self, event_type: str, **payload: Any) -> None:
        """Send one event to the GUI without touching Tkinter widgets."""
        try:
            self.callback(event_type, payload)
        except Exception:
            # A closed GUI must not crash the network worker.
            pass

    def log(self, message: str) -> None:
        self.logger.info(message)
        self.emit("log", message=message)

    def status(self, message: str, progress: Optional[float] = None) -> None:
        self.logger.info("STATUS | %s", message)
        payload: dict[str, Any] = {"message": message}
        if progress is not None:
            payload["progress"] = progress
        self.emit("status", **payload)

    def warning(self, message: str) -> None:
        self.logger.warning(message)
        self.emit("warning", message=message)

    def error(self, message: str) -> None:
        self.logger.error(message)
        self.emit("error", message=message)

    def report_exception(self, context: str, error: BaseException, notify: bool = True) -> None:
        self.logger.exception("%s | %s", context, error)
        if notify:
            self.emit("error", message=f"{context}: {friendly_error_message(error)}")

    def _send_packet(self, connection: socket.socket, packet: dict) -> int:
        """Serialise socket writes so two GUI workers cannot interleave data."""
        with self.send_lock:
            size = NetworkProtocol.send_packet(connection, packet)
        try:
            packet_type = NetworkProtocol.get_message_type(packet).value
        except Exception:
            packet_type = str(packet.get("type", "UNKNOWN"))
        self.logger.info(
            "TX_PACKET | type=%s | id=%s | framed_bytes=%s",
            packet_type,
            packet.get("packet_id", "unknown"),
            size,
        )
        return size

    def _register_waiter(self, packet_id: str) -> queue.Queue[dict[str, Any]]:
        waiter: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self._ack_waiters_lock:
            self._ack_waiters[packet_id] = waiter
        return waiter

    def _deliver_ack_or_error(self, packet: dict) -> bool:
        """Route ACK/ERROR packets to the worker waiting for them."""
        message_type = NetworkProtocol.get_message_type(packet)
        if message_type not in {MessageType.ACK, MessageType.ERROR}:
            return False

        packet_id = str(packet.get("payload", {}).get("received_packet_id", ""))
        if not packet_id:
            return False

        with self._ack_waiters_lock:
            waiter = self._ack_waiters.get(packet_id)

        if waiter is None:
            return False

        try:
            waiter.put_nowait(packet)
        except queue.Full:
            pass
        return True

    def _wait_for_response(
        self,
        packet_id: str,
        waiter: queue.Queue[dict[str, Any]],
        timeout: float = ACK_TIMEOUT_SECONDS,
    ) -> dict:
        try:
            response = waiter.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError("Timed out while waiting for the peer's response.") from error
        finally:
            with self._ack_waiters_lock:
                self._ack_waiters.pop(packet_id, None)

        response_type = NetworkProtocol.get_message_type(response)
        if response_type == MessageType.ERROR:
            raise ProtocolError(
                response.get("payload", {}).get("message", "The peer rejected the request.")
            )
        if response_type != MessageType.ACK:
            raise ProtocolError("Expected an ACK packet.")
        return response

    @staticmethod
    def fingerprint(value: bytes) -> str:
        digest = sha256(value).hexdigest().upper()
        return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))

    @staticmethod
    def validate_uuid(value: str, field: str) -> None:
        try:
            uuid.UUID(value)
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError(f"{field} is not a valid UUID.") from error

    def _cancel_waiters(self, message: str) -> None:
        """Unblock any worker waiting for an ACK during shutdown."""
        with self._ack_waiters_lock:
            waiters = list(self._ack_waiters.values())
            self._ack_waiters.clear()

        for waiter in waiters:
            packet = NetworkProtocol.create_packet(
                MessageType.ERROR,
                {"message": message, "received_packet_id": "shutdown"},
                sender="System",
            )
            try:
                waiter.put_nowait(packet)
            except queue.Full:
                pass


class AliceGUIBackend(BackendBase):
    """Real Alice TCP server used by the Tkinter interface."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5000

    def __init__(
        self,
        callback: BackendCallback,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        received_directory: str | Path = "received_files/alice_gui",
    ) -> None:
        super().__init__(callback, "Alice")
        self.host = host.strip()
        self.port = port
        self.received_directory = Path(received_directory)

        self.crypto_manager = CryptoManager()
        self.file_manager = FileTransferManager(self.crypto_manager)

        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.client_address: Optional[tuple[str, int]] = None

        self.session_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.public_key_packet_id: Optional[str] = None
        self.secure_session_ready = False

        self.chat_send_sequence = 0
        self.expected_bob_chat_sequence = 1

        self.incoming_manifest: Optional[FileManifest] = None
        self.incoming_assembler: Optional[IncomingFileAssembler] = None

    # ---------- lifecycle ----------

    def start(self) -> None:
        """Generate keys, listen, accept Bob and start the receive loop."""
        with self.lifecycle_lock:
            if self.server_socket is not None or self.client_socket is not None:
                raise RuntimeError("Alice's server is already running.")
            self.stop_event.clear()
            self.disconnecting_event.clear()
            self.session_key = None
            self.session_id = None
            self.public_key_packet_id = None
            self.secure_session_ready = False
            self.chat_send_sequence = 0
            self.expected_bob_chat_sequence = 1
            self.client_address = None
            self.incoming_manifest = None
            self.incoming_assembler = None

        try:
            self.status("Generating Alice's RSA-2048 key pair...", 10)
            self.log("Generating RSA-2048 key pair using PyCryptodome's secure random source.")
            self.crypto_manager.generate_rsa_key_pair()
            verification = self.crypto_manager.verify_rsa_parameters()
            if not verification.all_tests_passed:
                raise RuntimeError("Alice's RSA key failed mathematical verification.")

            self.log(
                f"RSA-2048 key generated; public-key fingerprint: "
                f"{self.crypto_manager.get_public_key_fingerprint()}"
            )
            self.log("Alice's RSA private key and prime factors remain in Alice's process only.")

            self._start_listening()
            self._accept_client()
            self._send_public_key()

            self.receiver_thread = threading.Thread(
                target=self._receive_loop,
                name="Alice-GUI-receiver",
                daemon=True,
            )
            self.receiver_thread.start()
        except Exception as error:
            self.report_exception(f"{self.role_name} startup failed", error)
            self.close(notify=True)
            raise

    def _start_listening(self) -> None:
        if not self.host:
            raise ValueError("Host cannot be empty.")
        if not 0 <= self.port <= 65535:
            raise ValueError("Port must be between 0 and 65535.")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(0.5)
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
        except OSError:
            server_socket.close()
            raise

        self.server_socket = server_socket
        self.port = int(server_socket.getsockname()[1])
        self.status(f"Listening on {self.host}:{self.port}; waiting for Bob...", 35)
        self.log(f"Length-prefixed TCP server listening on {self.host}:{self.port}.")

    def _accept_client(self) -> None:
        if self.server_socket is None:
            raise RuntimeError("Alice's server is not listening.")

        while not self.stop_event.is_set():
            try:
                connection, address = self.server_socket.accept()
                break
            except socket.timeout:
                continue
        else:
            raise RuntimeError("Alice's server was stopped before Bob connected.")

        connection.settimeout(None)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client_socket = connection
        self.client_address = (str(address[0]), int(address[1]))
        self.status(f"Bob connected from {address[0]}:{address[1]}", 50)
        self.log(f"TCP connection accepted from Bob at {address[0]}:{address[1]}.")

    def _send_public_key(self) -> None:
        public_key_pem = self.crypto_manager.export_public_key()
        packet = NetworkProtocol.create_packet(
            MessageType.PUBLIC_KEY,
            {
                "public_key": NetworkProtocol.encode_bytes(public_key_pem),
                "algorithm": "RSA",
                "key_format": "PEM",
                "key_size_bits": self.crypto_manager.get_key_size(),
                "fingerprint_sha256": self.crypto_manager.get_public_key_fingerprint(),
            },
            sender="Alice",
        )
        size = self._send_packet(self._require_connection(), packet)
        self.public_key_packet_id = packet["packet_id"]
        self.status("RSA public key sent to Bob; waiting for AES key exchange...", 65)
        self.log(f"Alice sent her RSA public key in a {size}-byte framed TCP packet.")

    # ---------- receiver and packet handlers ----------

    def _receive_loop(self) -> None:
        try:
            connection = self._require_connection()
            while not self.stop_event.is_set():
                packet = NetworkProtocol.receive_packet(connection)
                try:
                    packet_type = NetworkProtocol.get_message_type(packet).value
                except Exception:
                    packet_type = str(packet.get("type", "UNKNOWN"))
                self.logger.info(
                    "RX_PACKET | type=%s | id=%s",
                    packet_type,
                    packet.get("packet_id", "unknown"),
                )

                if self._deliver_ack_or_error(packet):
                    continue

                if not self._handle_packet(packet):
                    break
        except ConnectionClosedError as error:
            if self.stop_event.is_set() or self.disconnecting_event.is_set():
                self.log("Bob's TCP connection closed during the expected shutdown sequence.")
            else:
                self.warning(f"Unexpected Bob disconnection detected: {error}")
        except (OSError, ProtocolError, ConnectionError, RuntimeError, ValueError, TypeError) as error:
            if not self.stop_event.is_set():
                self.report_exception("Alice receiver loop failed", error)
        finally:
            self.close(notify=True)

    def _handle_packet(self, packet: dict) -> bool:
        message_type = NetworkProtocol.get_message_type(packet)

        if message_type == MessageType.ACK:
            payload = packet["payload"]
            if payload.get("received_packet_id") == self.public_key_packet_id:
                self.log("Bob acknowledged and verified Alice's RSA public key.")
            return True

        if message_type == MessageType.ENCRYPTED_AES_KEY:
            self._handle_encrypted_aes_key(packet)
            return True

        if message_type == MessageType.CHAT:
            self._handle_chat_packet(packet)
            return True

        if message_type == MessageType.FILE:
            self._handle_file_packet(packet)
            return True

        if message_type == MessageType.STATUS:
            self.log(f"Bob status: {packet['payload'].get('message', '')}")
            return True

        if message_type == MessageType.DISCONNECT:
            self.disconnecting_event.set()
            reason = packet.get("payload", {}).get("message", "Bob requested disconnection.")
            self.log(f"Bob requested disconnection: {reason}")
            self._send_ack(
                packet["packet_id"],
                "Alice acknowledged Bob's disconnect request.",
                {"secure_session_ended": self.session_key is not None},
            )
            return False

        self._send_error(packet["packet_id"], f"Unsupported packet type: {message_type.value}")
        return True

    def _handle_encrypted_aes_key(self, packet: dict) -> None:
        if self.session_key is not None:
            raise ProtocolError("A secure session already exists.")

        payload = packet["payload"]
        required = {
            "encrypted_key",
            "key_transport_algorithm",
            "oaep_hash",
            "rsa_key_size_bits",
            "aes_algorithm",
            "aes_key_size_bits",
            "public_key_fingerprint",
            "session_id",
        }
        missing = required - set(payload)
        if missing:
            raise ProtocolError(
                "ENCRYPTED_AES_KEY packet is missing: " + ", ".join(sorted(missing))
            )

        if payload["key_transport_algorithm"] != "RSA-OAEP":
            raise ProtocolError("Expected RSA-OAEP key transport.")
        if payload["oaep_hash"] != "SHA-256":
            raise ProtocolError("RSA-OAEP must use SHA-256.")
        if int(payload["rsa_key_size_bits"]) != 2048:
            raise ProtocolError("RSA key size must be 2048 bits.")
        if payload["aes_algorithm"] != "AES-GCM":
            raise ProtocolError("Session cipher must be AES-GCM.")
        if int(payload["aes_key_size_bits"]) != 256:
            raise ProtocolError("AES session key must be 256 bits.")
        if payload["public_key_fingerprint"] != self.crypto_manager.get_public_key_fingerprint():
            raise ProtocolError("The AES key was encrypted for another RSA public key.")

        self.validate_uuid(str(payload["session_id"]), "Session identifier")
        encrypted_key = NetworkProtocol.decode_bytes(payload["encrypted_key"])
        if len(encrypted_key) != 256:
            raise ProtocolError("RSA-2048 OAEP ciphertext must be 256 bytes.")

        recovered_key = self.crypto_manager.decrypt_aes_key(encrypted_key)
        if len(recovered_key) != 32:
            raise ProtocolError("Recovered AES key is not 32 bytes.")

        self.session_key = recovered_key
        self.session_id = str(payload["session_id"])
        self.secure_session_ready = True
        fingerprint = self.fingerprint(recovered_key)

        self._send_ack(
            packet["packet_id"],
            "Alice decrypted Bob's AES-256 session key successfully.",
            {
                "secure_session": True,
                "session_id": self.session_id,
                "aes_key_fingerprint": fingerprint,
            },
        )

        self.log("RSA-OAEP with SHA-256 successfully protected Bob's AES-256 session key.")
        self.log(f"AES-key fingerprint verified: {fingerprint}")
        self.status("Secure AES-256-GCM session established with Bob", 100)
        self.emit(
            "connected",
            message="Secure AES-256-GCM session established with Bob.",
            session_id=self.session_id,
        )

    def _handle_chat_packet(self, packet: dict) -> None:
        self._require_secure_session()
        if packet.get("sender") != "Bob":
            raise ProtocolError("Expected CHAT sender Bob.")

        payload = packet["payload"]
        sequence = int(payload["sequence"])
        if sequence != self.expected_bob_chat_sequence:
            raise ProtocolError(
                f"Expected Bob CHAT sequence {self.expected_bob_chat_sequence}, received {sequence}."
            )
        if payload["session_id"] != self.session_id:
            raise ProtocolError("CHAT packet belongs to another session.")

        encrypted = AESGCMEncryptedData(
            nonce=NetworkProtocol.decode_bytes(payload["nonce"]),
            ciphertext=NetworkProtocol.decode_bytes(payload["ciphertext"]),
            tag=NetworkProtocol.decode_bytes(payload["tag"]),
        )
        plaintext = self.crypto_manager.decrypt_text(
            encrypted_data=encrypted,
            aes_key=self.session_key,
            associated_data=self._chat_aad("Bob", sequence),
        )
        self.expected_bob_chat_sequence += 1
        self.log(f"Authenticated Bob's AES-GCM CHAT sequence {sequence}: PASS")
        self.emit("chat", sender="Bob", message=plaintext, local=False)

    def _handle_file_packet(self, packet: dict) -> None:
        self._require_secure_session()
        if packet.get("sender") != "Bob":
            raise ProtocolError("Expected FILE sender Bob.")

        payload = packet["payload"]
        action = payload.get("action")
        if action == "MANIFEST":
            self._begin_incoming_file(payload)
        elif action == "CHUNK":
            self._accept_incoming_chunk(payload)
        elif action == "COMPLETE":
            self._complete_incoming_file(packet, payload)
        else:
            raise ProtocolError(f"Unsupported FILE action: {action!r}")

    def _begin_incoming_file(self, payload: dict) -> None:
        if self.incoming_assembler is not None:
            raise ProtocolError("Another incoming file transfer is active.")

        manifest = FileManifest.from_payload(payload["manifest"])
        self.file_manager.validate_manifest(manifest)
        self.incoming_manifest = manifest
        self.incoming_assembler = IncomingFileAssembler(
            self.file_manager,
            manifest,
            self.received_directory,
        )
        self.log(
            f"Accepted Bob's FILE manifest: {manifest.file_name}, "
            f"{manifest.file_size} bytes, {manifest.total_chunks} chunks."
        )
        self.emit(
            "file_started",
            sender="Bob",
            file_name=manifest.file_name,
            total_chunks=manifest.total_chunks,
            file_size=manifest.file_size,
        )

    def _accept_incoming_chunk(self, payload: dict) -> None:
        if self.incoming_manifest is None or self.incoming_assembler is None:
            raise ProtocolError("FILE chunk arrived before its manifest.")

        chunk = EncryptedFileChunk.from_payload(payload["chunk"])
        bytes_written = self.incoming_assembler.add_chunk(
            encrypted_chunk=chunk,
            aes_key=self.session_key,
            session_id=self.session_id,
            sender="Bob",
        )
        progress = ((chunk.chunk_index + 1) / self.incoming_manifest.total_chunks) * 100
        self.log(
            f"Authenticated Bob FILE chunk {chunk.chunk_index + 1}/"
            f"{self.incoming_manifest.total_chunks} ({bytes_written} plaintext bytes)."
        )
        self.emit(
            "file_progress",
            message=f"Receiving {self.incoming_manifest.file_name}",
            progress=progress,
        )

    def _complete_incoming_file(self, packet: dict, payload: dict) -> None:
        if self.incoming_manifest is None or self.incoming_assembler is None:
            raise ProtocolError("FILE COMPLETE arrived without an active transfer.")
        if payload.get("transfer_id") != self.incoming_manifest.transfer_id:
            raise ProtocolError("FILE COMPLETE transfer ID does not match.")

        manifest = self.incoming_manifest
        assembler = self.incoming_assembler
        try:
            final_path = assembler.finalise()
        finally:
            self.incoming_manifest = None
            self.incoming_assembler = None

        received_hash = self.file_manager.calculate_file_sha256(final_path)
        self._send_ack(
            packet["packet_id"],
            "Alice authenticated, reconstructed and verified Bob's file.",
            {
                "transfer_id": manifest.transfer_id,
                "file_name": manifest.file_name,
                "file_size": manifest.file_size,
                "sha256": received_hash,
                "file_verified": True,
            },
        )
        self.log(
            f"Bob's encrypted file passed AES-GCM authentication and SHA-256 verification: "
            f"{final_path}"
        )
        self.emit(
            "file_received",
            sender="Bob",
            file_name=manifest.file_name,
            path=str(final_path),
            sha256=received_hash,
            message=f"Verified file received from Bob: {manifest.file_name}",
        )

    # ---------- GUI actions ----------

    def send_chat(self, plaintext: str) -> None:
        self._require_secure_session()
        text = plaintext.strip()
        if not text:
            raise ValueError("Chat message cannot be empty.")
        if len(text.encode("utf-8")) > 64 * 1024:
            raise ValueError("Chat message exceeds the maximum permitted size.")

        self.chat_send_sequence += 1
        sequence = self.chat_send_sequence
        encrypted = self.crypto_manager.encrypt_text(
            plaintext=text,
            aes_key=self.session_key,
            associated_data=self._chat_aad("Alice", sequence),
        )
        packet = NetworkProtocol.create_packet(
            MessageType.CHAT,
            {
                "algorithm": "AES-256-GCM",
                "session_id": self.session_id,
                "sequence": sequence,
                "nonce": NetworkProtocol.encode_bytes(encrypted.nonce),
                "ciphertext": NetworkProtocol.encode_bytes(encrypted.ciphertext),
                "tag": NetworkProtocol.encode_bytes(encrypted.tag),
            },
            sender="Alice",
        )
        self._send_packet(self._require_connection(), packet)
        self.log(
            f"Sent AES-GCM CHAT sequence {sequence}; nonce={len(encrypted.nonce)} bytes, "
            f"tag={len(encrypted.tag)} bytes."
        )
        self.emit("chat", sender="Alice", message=text, local=True)

    def send_file(self, file_path: str | Path) -> None:
        self._require_secure_session()
        connection = self._require_connection()
        manifest = self.file_manager.prepare_manifest(file_path)

        manifest_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {"action": "MANIFEST", "manifest": manifest.to_payload()},
            sender="Alice",
        )
        self._send_packet(connection, manifest_packet)
        self.log(
            f"Sending encrypted file to Bob: {manifest.file_name}, "
            f"{manifest.file_size} bytes, SHA-256={manifest.sha256_hex}."
        )

        for chunk in self.file_manager.iter_encrypted_chunks(
            file_path=file_path,
            aes_key=self.session_key,
            session_id=self.session_id,
            sender="Alice",
            manifest=manifest,
        ):
            packet = NetworkProtocol.create_packet(
                MessageType.FILE,
                {"action": "CHUNK", "chunk": chunk.to_payload()},
                sender="Alice",
            )
            self._send_packet(connection, packet)
            progress = ((chunk.chunk_index + 1) / manifest.total_chunks) * 100
            self.emit(
                "file_progress",
                message=f"Sending {manifest.file_name}",
                progress=progress,
            )
            self.log(
                f"Sent encrypted FILE chunk {chunk.chunk_index + 1}/{manifest.total_chunks}."
            )

        complete_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {
                "action": "COMPLETE",
                "transfer_id": manifest.transfer_id,
                "file_size": manifest.file_size,
                "sha256": manifest.sha256_hex,
            },
            sender="Alice",
        )
        waiter = self._register_waiter(complete_packet["packet_id"])
        self._send_packet(connection, complete_packet)
        response = self._wait_for_response(complete_packet["packet_id"], waiter)
        ack = response["payload"]
        if not ack.get("file_verified"):
            raise ProtocolError("Bob did not confirm file verification.")
        if ack.get("sha256") != manifest.sha256_hex:
            raise ProtocolError("Bob reported a different file SHA-256 value.")

        self.log("Bob authenticated and verified Alice's encrypted file: PASS")
        self.emit(
            "file_sent",
            file_name=manifest.file_name,
            path=str(Path(file_path).resolve()),
            sha256=manifest.sha256_hex,
            message=f"Encrypted file sent and verified by Bob: {manifest.file_name}",
        )

    def disconnect(self, reason: str = "Alice ended the GUI session.") -> None:
        self.disconnecting_event.set()
        self.logger.info("DISCONNECT_REQUESTED | reason=%s", reason)
        if self.client_socket is None:
            self.close(notify=True)
            return

        try:
            packet = NetworkProtocol.create_packet(
                MessageType.DISCONNECT,
                {"message": reason, "secure_session": self.session_key is not None},
                sender="Alice",
            )
            waiter = self._register_waiter(packet["packet_id"])
            self._send_packet(self._require_connection(), packet)
            self._wait_for_response(packet["packet_id"], waiter, timeout=5.0)
            self.log("Bob acknowledged Alice's disconnect request.")
        except Exception as error:
            self.log(f"Disconnect acknowledgement was not completed: {error}")
        finally:
            self.close(notify=True)

    # ---------- helpers ----------

    def _send_ack(self, packet_id: str, message: str, extra: Optional[dict] = None) -> None:
        payload = {"message": message, "received_packet_id": packet_id}
        if extra:
            payload.update(extra)
        packet = NetworkProtocol.create_packet(MessageType.ACK, payload, sender="Alice")
        self._send_packet(self._require_connection(), packet)

    def _send_error(self, packet_id: str, message: str) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ERROR,
            {"message": message, "received_packet_id": packet_id},
            sender="Alice",
        )
        self._send_packet(self._require_connection(), packet)

    def _chat_aad(self, sender: str, sequence: int) -> bytes:
        self._require_secure_session()
        return f"CHAT|{self.session_id}|{sender}|{sequence}".encode("utf-8")

    def _require_secure_session(self) -> None:
        if not self.secure_session_ready or self.session_key is None or self.session_id is None:
            raise RuntimeError("Secure session is not ready.")

    def _require_connection(self) -> socket.socket:
        if self.client_socket is None or self.client_socket.fileno() < 0:
            raise RuntimeError("Bob is not connected.")
        return self.client_socket

    def close(self, notify: bool = False) -> None:
        with self.lifecycle_lock:
            already_closed = self.server_socket is None and self.client_socket is None
            self.stop_event.set()
            self.disconnecting_event.set()

            if self.incoming_assembler is not None:
                self.incoming_assembler.abort()
                self.incoming_assembler = None
                self.incoming_manifest = None

            if self.client_socket is not None:
                try:
                    self.client_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.client_socket.close()
                except OSError:
                    pass
                self.client_socket = None

            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except OSError:
                    pass
                self.server_socket = None

            self.session_key = None
            self.session_id = None
            self.secure_session_ready = False
            self._cancel_waiters("Alice's server closed before the operation completed.")

        if notify and not already_closed:
            self.logger.info("SESSION_END | role=Alice | session_key_reference_cleared=true")
            self.log("Session-key reference cleared; Alice's TCP server stopped safely.")
            self.emit("disconnected", message="Alice's secure server stopped safely.")


class BobGUIBackend(BackendBase):
    """Real Bob TCP client used by the Tkinter interface."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5000

    def __init__(
        self,
        callback: BackendCallback,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        received_directory: str | Path = "received_files/bob_gui",
    ) -> None:
        super().__init__(callback, "Bob")
        self.host = host.strip()
        self.port = port
        self.received_directory = Path(received_directory)

        self.crypto_manager = CryptoManager()
        self.file_manager = FileTransferManager(self.crypto_manager)

        self.connection: Optional[socket.socket] = None
        self.session_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.secure_session_ready = False

        self.chat_send_sequence = 0
        self.expected_alice_chat_sequence = 1

        self.incoming_manifest: Optional[FileManifest] = None
        self.incoming_assembler: Optional[IncomingFileAssembler] = None

    # ---------- lifecycle and handshake ----------

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.connection is not None:
                raise RuntimeError("Bob is already connected.")
            self.stop_event.clear()
            self.disconnecting_event.clear()
            self.session_key = None
            self.session_id = None
            self.secure_session_ready = False
            self.chat_send_sequence = 0
            self.expected_alice_chat_sequence = 1
            self.incoming_manifest = None
            self.incoming_assembler = None

        try:
            self.status(f"Connecting to Alice at {self.host}:{self.port}...", 20)
            self._connect()
            public_key_packet = self._receive_public_key()
            self._send_public_key_ack(public_key_packet)
            self._establish_secure_session()

            self.receiver_thread = threading.Thread(
                target=self._receive_loop,
                name="Bob-GUI-receiver",
                daemon=True,
            )
            self.receiver_thread.start()
        except Exception as error:
            self.report_exception(f"{self.role_name} startup failed", error)
            self.close(notify=True)
            raise

    def _connect(self) -> None:
        if not self.host:
            raise ValueError("Host cannot be empty.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(10.0)
        try:
            connection.connect((self.host, self.port))
        except OSError:
            connection.close()
            raise
        connection.settimeout(None)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection = connection
        self.status("TCP connection to Alice established", 40)
        self.log(f"Connected to Alice at {self.host}:{self.port} using TCP.")

    def _receive_public_key(self) -> dict:
        packet = NetworkProtocol.receive_packet(self._require_connection())
        if NetworkProtocol.get_message_type(packet) != MessageType.PUBLIC_KEY:
            raise ProtocolError("Expected Alice's PUBLIC_KEY packet.")

        payload = packet["payload"]
        key = self.crypto_manager.import_public_key(
            NetworkProtocol.decode_bytes(payload["public_key"])
        )
        if key.size_in_bits() != 2048:
            raise ValueError("Alice's RSA key is not 2048 bits.")
        if self.crypto_manager.get_public_key_fingerprint() != payload["fingerprint_sha256"]:
            raise ValueError("Alice's public-key fingerprint failed verification.")
        if self.crypto_manager.has_private_key:
            raise ValueError("Bob unexpectedly received private RSA material.")

        self.status("Alice's RSA-2048 public key verified", 60)
        self.log(
            f"Alice's RSA public-key fingerprint verified: "
            f"{self.crypto_manager.get_public_key_fingerprint()}"
        )
        self.log("Bob possesses only Alice's public key; no private RSA material was received.")
        return packet

    def _send_public_key_ack(self, public_key_packet: dict) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ACK,
            {
                "message": "Alice's RSA public key was received and verified by Bob.",
                "received_packet_id": public_key_packet["packet_id"],
                "public_key_fingerprint": self.crypto_manager.get_public_key_fingerprint(),
            },
            sender="Bob",
        )
        self._send_packet(self._require_connection(), packet)

    def _establish_secure_session(self) -> None:
        connection = self._require_connection()
        self.session_key = self.crypto_manager.generate_aes_key()
        self.session_id = str(uuid.uuid4())
        fingerprint = self.fingerprint(self.session_key)
        encrypted_key = self.crypto_manager.encrypt_aes_key(self.session_key)

        packet = NetworkProtocol.create_packet(
            MessageType.ENCRYPTED_AES_KEY,
            {
                "encrypted_key": NetworkProtocol.encode_bytes(encrypted_key),
                "key_transport_algorithm": "RSA-OAEP",
                "oaep_hash": "SHA-256",
                "rsa_key_size_bits": 2048,
                "aes_algorithm": "AES-GCM",
                "aes_key_size_bits": 256,
                "public_key_fingerprint": self.crypto_manager.get_public_key_fingerprint(),
                "session_id": self.session_id,
            },
            sender="Bob",
        )
        self._send_packet(connection, packet)
        self.status("RSA-OAEP encrypted AES key sent to Alice", 80)

        response = NetworkProtocol.receive_packet(connection)
        if NetworkProtocol.get_message_type(response) != MessageType.ACK:
            raise ProtocolError("Alice did not acknowledge the AES key.")
        payload = response["payload"]
        if payload.get("received_packet_id") != packet["packet_id"]:
            raise ProtocolError("Alice acknowledged the wrong AES-key packet.")
        if payload.get("session_id") != self.session_id:
            raise ProtocolError("Alice confirmed another session ID.")
        if payload.get("aes_key_fingerprint") != fingerprint:
            raise ValueError("Alice recovered a different AES key.")

        self.secure_session_ready = True
        self.logger.info("SESSION_ESTABLISHED | role=Bob | session_id=%s | cipher=AES-256-GCM", self.session_id)
        self.log("RSA-OAEP with SHA-256 protected the AES-256 session key.")
        self.log(f"AES-key fingerprint matched Alice's recovered key: {fingerprint}")
        self.status("Secure AES-256-GCM session established with Alice", 100)
        self.emit(
            "connected",
            message="Secure AES-256-GCM session established with Alice.",
            session_id=self.session_id,
        )

    # ---------- receiver and packet handlers ----------

    def _receive_loop(self) -> None:
        try:
            connection = self._require_connection()
            while not self.stop_event.is_set():
                packet = NetworkProtocol.receive_packet(connection)
                try:
                    packet_type = NetworkProtocol.get_message_type(packet).value
                except Exception:
                    packet_type = str(packet.get("type", "UNKNOWN"))
                self.logger.info(
                    "RX_PACKET | type=%s | id=%s",
                    packet_type,
                    packet.get("packet_id", "unknown"),
                )

                if self._deliver_ack_or_error(packet):
                    continue

                if not self._handle_packet(packet):
                    break
        except ConnectionClosedError as error:
            if self.stop_event.is_set() or self.disconnecting_event.is_set():
                self.log("Alice's TCP connection closed during the expected shutdown sequence.")
            else:
                self.warning(f"Unexpected Alice disconnection detected: {error}")
        except (OSError, ProtocolError, ConnectionError, RuntimeError, ValueError, TypeError) as error:
            if not self.stop_event.is_set():
                self.report_exception("Bob receiver loop failed", error)
        finally:
            self.close(notify=True)

    def _handle_packet(self, packet: dict) -> bool:
        message_type = NetworkProtocol.get_message_type(packet)

        if message_type == MessageType.CHAT:
            self._handle_chat_packet(packet)
            return True
        if message_type == MessageType.FILE:
            self._handle_file_packet(packet)
            return True
        if message_type == MessageType.STATUS:
            self.log(f"Alice status: {packet['payload'].get('message', '')}")
            return True
        if message_type == MessageType.DISCONNECT:
            self.disconnecting_event.set()
            reason = packet.get("payload", {}).get("message", "Alice requested disconnection.")
            self.log(f"Alice requested disconnection: {reason}")
            self._send_ack(
                packet["packet_id"],
                "Bob acknowledged Alice's disconnect request.",
                {"secure_session_ended": self.session_key is not None},
            )
            return False
        if message_type == MessageType.ACK:
            self.log(f"Received unsolicited ACK from Alice: {packet['payload'].get('message', '')}")
            return True
        if message_type == MessageType.ERROR:
            raise ProtocolError(packet.get("payload", {}).get("message", "Alice reported an error."))

        self._send_error(packet["packet_id"], f"Unsupported packet type: {message_type.value}")
        return True

    def _handle_chat_packet(self, packet: dict) -> None:
        self._require_secure_session()
        if packet.get("sender") != "Alice":
            raise ProtocolError("Expected CHAT sender Alice.")

        payload = packet["payload"]
        sequence = int(payload["sequence"])
        if sequence != self.expected_alice_chat_sequence:
            raise ProtocolError(
                f"Expected Alice CHAT sequence {self.expected_alice_chat_sequence}, received {sequence}."
            )
        if payload["session_id"] != self.session_id:
            raise ProtocolError("CHAT packet belongs to another session.")

        encrypted = AESGCMEncryptedData(
            nonce=NetworkProtocol.decode_bytes(payload["nonce"]),
            ciphertext=NetworkProtocol.decode_bytes(payload["ciphertext"]),
            tag=NetworkProtocol.decode_bytes(payload["tag"]),
        )
        plaintext = self.crypto_manager.decrypt_text(
            encrypted_data=encrypted,
            aes_key=self.session_key,
            associated_data=self._chat_aad("Alice", sequence),
        )
        self.expected_alice_chat_sequence += 1
        self.log(f"Authenticated Alice's AES-GCM CHAT sequence {sequence}: PASS")
        self.emit("chat", sender="Alice", message=plaintext, local=False)

    def _handle_file_packet(self, packet: dict) -> None:
        self._require_secure_session()
        if packet.get("sender") != "Alice":
            raise ProtocolError("Expected FILE sender Alice.")

        payload = packet["payload"]
        action = payload.get("action")
        if action == "MANIFEST":
            self._begin_incoming_file(payload)
        elif action == "CHUNK":
            self._accept_incoming_chunk(payload)
        elif action == "COMPLETE":
            self._complete_incoming_file(packet, payload)
        else:
            raise ProtocolError(f"Unsupported FILE action: {action!r}")

    def _begin_incoming_file(self, payload: dict) -> None:
        if self.incoming_assembler is not None:
            raise ProtocolError("Another incoming file transfer is active.")

        manifest = FileManifest.from_payload(payload["manifest"])
        self.file_manager.validate_manifest(manifest)
        self.incoming_manifest = manifest
        self.incoming_assembler = IncomingFileAssembler(
            self.file_manager,
            manifest,
            self.received_directory,
        )
        self.log(
            f"Accepted Alice's FILE manifest: {manifest.file_name}, "
            f"{manifest.file_size} bytes, {manifest.total_chunks} chunks."
        )
        self.emit(
            "file_started",
            sender="Alice",
            file_name=manifest.file_name,
            total_chunks=manifest.total_chunks,
            file_size=manifest.file_size,
        )

    def _accept_incoming_chunk(self, payload: dict) -> None:
        if self.incoming_manifest is None or self.incoming_assembler is None:
            raise ProtocolError("FILE chunk arrived before its manifest.")

        chunk = EncryptedFileChunk.from_payload(payload["chunk"])
        bytes_written = self.incoming_assembler.add_chunk(
            encrypted_chunk=chunk,
            aes_key=self.session_key,
            session_id=self.session_id,
            sender="Alice",
        )
        progress = ((chunk.chunk_index + 1) / self.incoming_manifest.total_chunks) * 100
        self.log(
            f"Authenticated Alice FILE chunk {chunk.chunk_index + 1}/"
            f"{self.incoming_manifest.total_chunks} ({bytes_written} plaintext bytes)."
        )
        self.emit(
            "file_progress",
            message=f"Receiving {self.incoming_manifest.file_name}",
            progress=progress,
        )

    def _complete_incoming_file(self, packet: dict, payload: dict) -> None:
        if self.incoming_manifest is None or self.incoming_assembler is None:
            raise ProtocolError("FILE COMPLETE arrived without an active transfer.")
        if payload.get("transfer_id") != self.incoming_manifest.transfer_id:
            raise ProtocolError("FILE COMPLETE transfer ID does not match.")

        manifest = self.incoming_manifest
        assembler = self.incoming_assembler
        try:
            final_path = assembler.finalise()
        finally:
            self.incoming_manifest = None
            self.incoming_assembler = None

        verified_hash = self.file_manager.calculate_file_sha256(final_path)
        self._send_ack(
            packet["packet_id"],
            "Bob authenticated, reconstructed and verified Alice's file.",
            {
                "transfer_id": manifest.transfer_id,
                "file_name": manifest.file_name,
                "file_size": manifest.file_size,
                "sha256": verified_hash,
                "file_verified": True,
            },
        )
        self.log(
            f"Alice's encrypted file passed AES-GCM authentication and SHA-256 verification: "
            f"{final_path}"
        )
        self.emit(
            "file_received",
            sender="Alice",
            file_name=manifest.file_name,
            path=str(final_path),
            sha256=verified_hash,
            message=f"Verified file received from Alice: {manifest.file_name}",
        )

    # ---------- GUI actions ----------

    def send_chat(self, plaintext: str) -> None:
        self._require_secure_session()
        text = plaintext.strip()
        if not text:
            raise ValueError("Chat message cannot be empty.")
        if len(text.encode("utf-8")) > 64 * 1024:
            raise ValueError("Chat message exceeds the maximum permitted size.")

        self.chat_send_sequence += 1
        sequence = self.chat_send_sequence
        encrypted = self.crypto_manager.encrypt_text(
            plaintext=text,
            aes_key=self.session_key,
            associated_data=self._chat_aad("Bob", sequence),
        )
        packet = NetworkProtocol.create_packet(
            MessageType.CHAT,
            {
                "algorithm": "AES-256-GCM",
                "session_id": self.session_id,
                "sequence": sequence,
                "nonce": NetworkProtocol.encode_bytes(encrypted.nonce),
                "ciphertext": NetworkProtocol.encode_bytes(encrypted.ciphertext),
                "tag": NetworkProtocol.encode_bytes(encrypted.tag),
            },
            sender="Bob",
        )
        self._send_packet(self._require_connection(), packet)
        self.log(
            f"Sent AES-GCM CHAT sequence {sequence}; nonce={len(encrypted.nonce)} bytes, "
            f"tag={len(encrypted.tag)} bytes."
        )
        self.emit("chat", sender="Bob", message=text, local=True)

    def send_file(self, file_path: str | Path) -> None:
        self._require_secure_session()
        connection = self._require_connection()
        manifest = self.file_manager.prepare_manifest(file_path)

        manifest_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {"action": "MANIFEST", "manifest": manifest.to_payload()},
            sender="Bob",
        )
        self._send_packet(connection, manifest_packet)
        self.log(
            f"Sending encrypted file to Alice: {manifest.file_name}, "
            f"{manifest.file_size} bytes, SHA-256={manifest.sha256_hex}."
        )

        for chunk in self.file_manager.iter_encrypted_chunks(
            file_path=file_path,
            aes_key=self.session_key,
            session_id=self.session_id,
            sender="Bob",
            manifest=manifest,
        ):
            packet = NetworkProtocol.create_packet(
                MessageType.FILE,
                {"action": "CHUNK", "chunk": chunk.to_payload()},
                sender="Bob",
            )
            self._send_packet(connection, packet)
            progress = ((chunk.chunk_index + 1) / manifest.total_chunks) * 100
            self.emit(
                "file_progress",
                message=f"Sending {manifest.file_name}",
                progress=progress,
            )
            self.log(
                f"Sent encrypted FILE chunk {chunk.chunk_index + 1}/{manifest.total_chunks}."
            )

        complete_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {
                "action": "COMPLETE",
                "transfer_id": manifest.transfer_id,
                "file_size": manifest.file_size,
                "sha256": manifest.sha256_hex,
            },
            sender="Bob",
        )
        waiter = self._register_waiter(complete_packet["packet_id"])
        self._send_packet(connection, complete_packet)
        response = self._wait_for_response(complete_packet["packet_id"], waiter)
        ack = response["payload"]
        if not ack.get("file_verified"):
            raise ProtocolError("Alice did not confirm file verification.")
        if ack.get("sha256") != manifest.sha256_hex:
            raise ProtocolError("Alice reported a different file SHA-256 value.")

        self.log("Alice authenticated and verified Bob's encrypted file: PASS")
        self.emit(
            "file_sent",
            file_name=manifest.file_name,
            path=str(Path(file_path).resolve()),
            sha256=manifest.sha256_hex,
            message=f"Encrypted file sent and verified by Alice: {manifest.file_name}",
        )

    def disconnect(self, reason: str = "Bob ended the GUI session.") -> None:
        self.disconnecting_event.set()
        self.logger.info("DISCONNECT_REQUESTED | reason=%s", reason)
        if self.connection is None:
            self.close(notify=True)
            return

        try:
            packet = NetworkProtocol.create_packet(
                MessageType.DISCONNECT,
                {"message": reason, "secure_session": self.session_key is not None},
                sender="Bob",
            )
            waiter = self._register_waiter(packet["packet_id"])
            self._send_packet(self._require_connection(), packet)
            self._wait_for_response(packet["packet_id"], waiter, timeout=5.0)
            self.log("Alice acknowledged Bob's disconnect request.")
        except Exception as error:
            self.log(f"Disconnect acknowledgement was not completed: {error}")
        finally:
            self.close(notify=True)

    # ---------- helpers ----------

    def _send_ack(self, packet_id: str, message: str, extra: Optional[dict] = None) -> None:
        payload = {"message": message, "received_packet_id": packet_id}
        if extra:
            payload.update(extra)
        packet = NetworkProtocol.create_packet(MessageType.ACK, payload, sender="Bob")
        self._send_packet(self._require_connection(), packet)

    def _send_error(self, packet_id: str, message: str) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ERROR,
            {"message": message, "received_packet_id": packet_id},
            sender="Bob",
        )
        self._send_packet(self._require_connection(), packet)

    def _chat_aad(self, sender: str, sequence: int) -> bytes:
        self._require_secure_session()
        return f"CHAT|{self.session_id}|{sender}|{sequence}".encode("utf-8")

    def _require_secure_session(self) -> None:
        if not self.secure_session_ready or self.session_key is None or self.session_id is None:
            raise RuntimeError("Secure session is not ready.")

    def _require_connection(self) -> socket.socket:
        if self.connection is None or self.connection.fileno() < 0:
            raise RuntimeError("Bob is not connected.")
        return self.connection

    def close(self, notify: bool = False) -> None:
        with self.lifecycle_lock:
            already_closed = self.connection is None
            self.stop_event.set()
            self.disconnecting_event.set()

            if self.incoming_assembler is not None:
                self.incoming_assembler.abort()
                self.incoming_assembler = None
                self.incoming_manifest = None

            if self.connection is not None:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.connection.close()
                except OSError:
                    pass
                self.connection = None

            self.session_key = None
            self.session_id = None
            self.secure_session_ready = False
            self._cancel_waiters("Bob's client closed before the operation completed.")

        if notify and not already_closed:
            self.logger.info("SESSION_END | role=Bob | session_key_reference_cleared=true")
            self.log("Session-key reference cleared; Bob's TCP client stopped safely.")
            self.emit("disconnected", message="Bob's secure client stopped safely.")
