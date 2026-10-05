"""
Stage 11B Alice server: RSA-OAEP key exchange, AES-256-GCM chat,
and two-way encrypted file transfer over a length-prefixed TCP protocol.
"""
from __future__ import annotations

import argparse
import socket
import uuid
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Optional

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


class AliceServerState(str, Enum):
    STOPPED = "STOPPED"
    GENERATING_KEYS = "GENERATING_KEYS"
    LISTENING = "LISTENING"
    CLIENT_CONNECTED = "CLIENT_CONNECTED"
    PUBLIC_KEY_SENT = "PUBLIC_KEY_SENT"
    SECURE_SESSION_READY = "SECURE_SESSION_READY"
    DISCONNECTING = "DISCONNECTING"


class AliceServer:
    """Alice's secure TCP server."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5000

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        automatic_chat_reply: bool = True,
        received_directory: str | Path = "received_files/alice",
    ) -> None:
        self.host = host.strip()
        self.port = port
        self.automatic_chat_reply = automatic_chat_reply
        self.received_directory = Path(received_directory)

        self.crypto_manager = CryptoManager()
        self.file_manager = FileTransferManager(self.crypto_manager)

        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.client_address: Optional[tuple[str, int]] = None

        self.session_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.public_key_packet_id: Optional[str] = None

        self.chat_send_sequence = 0
        self.expected_bob_chat_sequence = 1

        self.incoming_manifest: Optional[FileManifest] = None
        self.incoming_assembler: Optional[IncomingFileAssembler] = None
        self.reply_file_sent = False

        self.state = AliceServerState.STOPPED

    def run(self) -> None:
        self._print_banner()
        try:
            self._generate_rsa_key_pair()
            self._start_listening()
            self._accept_client()
            self._send_public_key()
            self._receive_loop()
        except KeyboardInterrupt:
            print("\n[Alice] Server stopped by the user.")
        except (
            OSError,
            ProtocolError,
            ConnectionError,
            RuntimeError,
            ValueError,
            TypeError,
        ) as error:
            print(f"\n[Alice] Application error: {error}")
        finally:
            self.shutdown()

    # ------------------------------------------------------------------
    # Startup and key exchange
    # ------------------------------------------------------------------

    def _generate_rsa_key_pair(self) -> None:
        self._set_state(AliceServerState.GENERATING_KEYS)
        print("\n[Alice] Generating RSA-2048 key pair...")
        self.crypto_manager.generate_rsa_key_pair()

        verification = self.crypto_manager.verify_rsa_parameters()
        if not verification.all_tests_passed:
            raise RuntimeError("Alice's RSA key failed verification.")

        print("[Alice] RSA-2048 key pair generated and verified.")
        print(f"[Alice] RSA modulus size: {self.crypto_manager.get_key_size()} bits")
        print("[Alice] Public-key SHA-256 fingerprint:")
        print(self.crypto_manager.get_public_key_fingerprint())
        print("[Alice] Private RSA material remains only on Alice.")

    def _start_listening(self) -> None:
        if not self.host:
            raise ValueError("Host cannot be empty.")
        if not 0 <= self.port <= 65535:
            raise ValueError("Port must be between 0 and 65535.")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
        except OSError:
            server_socket.close()
            raise

        self.server_socket = server_socket
        self.port = int(server_socket.getsockname()[1])
        self._set_state(AliceServerState.LISTENING)
        print(f"\n[Alice] Server listening on {self.host}:{self.port}")
        print("[Alice] Waiting for Bob to connect...")

    def _accept_client(self) -> None:
        if self.server_socket is None:
            raise RuntimeError("Server is not listening.")

        connection, address = self.server_socket.accept()
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client_socket = connection
        self.client_address = (str(address[0]), int(address[1]))
        self._set_state(AliceServerState.CLIENT_CONNECTED)
        print(f"[Alice] Bob connected from {address[0]}:{address[1]}")

    def _send_public_key(self) -> None:
        connection = self._require_connection()
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
        size = NetworkProtocol.send_packet(connection, packet)
        self.public_key_packet_id = packet["packet_id"]
        self._set_state(AliceServerState.PUBLIC_KEY_SENT)
        print(f"[Alice] RSA public key sent to Bob ({size} framed bytes).")

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
            raise ProtocolError("AES key was encrypted for another RSA public key.")

        self._validate_uuid(str(payload["session_id"]), "Session identifier")
        encrypted_key = NetworkProtocol.decode_bytes(payload["encrypted_key"])
        if len(encrypted_key) != 256:
            raise ProtocolError("RSA-2048 ciphertext must be 256 bytes.")

        recovered_key = self.crypto_manager.decrypt_aes_key(encrypted_key)
        if len(recovered_key) != 32:
            raise ProtocolError("Recovered AES key is not 32 bytes.")

        self.session_key = recovered_key
        self.session_id = str(payload["session_id"])
        fingerprint = self._fingerprint(recovered_key)
        self._set_state(AliceServerState.SECURE_SESSION_READY)

        print("[Alice] AES-256 session key decrypted successfully.")
        print(f"[Alice] Session identifier: {self.session_id}")
        print(f"[Alice] AES key length: {len(recovered_key) * 8} bits")
        print("[Alice] AES-key SHA-256 fingerprint:")
        print(fingerprint)

        self._send_ack(
            packet["packet_id"],
            "Alice decrypted Bob's AES-256 session key successfully.",
            {
                "secure_session": True,
                "session_id": self.session_id,
                "aes_key_fingerprint": fingerprint,
            },
        )
        print("[Alice] SECURE AES-256 SESSION ESTABLISHED SUCCESSFULLY.")

    # ------------------------------------------------------------------
    # Packet handling
    # ------------------------------------------------------------------

    def _receive_loop(self) -> None:
        connection = self._require_connection()
        while True:
            try:
                packet = NetworkProtocol.receive_packet(connection)
            except ConnectionClosedError as error:
                print(f"[Alice] Bob closed the connection: {error}")
                break

            if not self._handle_packet(packet):
                break

    def _handle_packet(self, packet: dict) -> bool:
        message_type = NetworkProtocol.get_message_type(packet)
        print(f"\n[Alice] Received {message_type.value} packet from {packet.get('sender')}.")

        if message_type == MessageType.ACK:
            payload = packet["payload"]
            if payload.get("received_packet_id") == self.public_key_packet_id:
                print("[Alice] Bob confirmed receipt of Alice's RSA public key.")
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
            print(f"[Alice] Bob status: {packet['payload'].get('message')}")
            return True

        if message_type == MessageType.DISCONNECT:
            print(f"[Alice] Disconnect request: {packet['payload'].get('message')}")
            self._send_ack(
                packet["packet_id"],
                "Alice acknowledged Bob's disconnect request.",
                {"secure_session_ended": self.session_key is not None},
            )
            self._set_state(AliceServerState.DISCONNECTING)
            return False

        self._send_error(packet["packet_id"], f"Unsupported packet type: {message_type.value}")
        return True

    # ------------------------------------------------------------------
    # Encrypted chat retained from Stage 10
    # ------------------------------------------------------------------

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
        print("[Alice] AES-GCM chat authentication: PASS")
        print(f"[Alice] Decrypted message from Bob: {plaintext}")

        if self.automatic_chat_reply:
            reply = f"Hello Bob. Alice authenticated chat message {sequence}."
        else:
            reply = input("Alice encrypted reply: ").strip() or "Alice authenticated the message."
        self._send_chat_message(reply)

    def _send_chat_message(self, plaintext: str) -> None:
        self._require_secure_session()
        connection = self._require_connection()
        self.chat_send_sequence += 1
        encrypted = self.crypto_manager.encrypt_text(
            plaintext=plaintext,
            aes_key=self.session_key,
            associated_data=self._chat_aad("Alice", self.chat_send_sequence),
        )
        packet = NetworkProtocol.create_packet(
            MessageType.CHAT,
            {
                "algorithm": "AES-256-GCM",
                "session_id": self.session_id,
                "sequence": self.chat_send_sequence,
                "nonce": NetworkProtocol.encode_bytes(encrypted.nonce),
                "ciphertext": NetworkProtocol.encode_bytes(encrypted.ciphertext),
                "tag": NetworkProtocol.encode_bytes(encrypted.tag),
            },
            sender="Alice",
        )
        NetworkProtocol.send_packet(connection, packet)
        print(f"[Alice] Encrypted CHAT sequence {self.chat_send_sequence} sent to Bob.")

    # ------------------------------------------------------------------
    # Two-way encrypted file transfer
    # ------------------------------------------------------------------

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
        print("[Alice] FILE manifest accepted.")
        print(f"[Alice] Incoming filename: {manifest.file_name}")
        print(f"[Alice] Incoming size: {manifest.file_size} bytes")
        print(f"[Alice] Total encrypted chunks: {manifest.total_chunks}")
        print(f"[Alice] Sender SHA-256: {manifest.sha256_hex}")

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
        print(
            f"[Alice] Authenticated FILE chunk {chunk.chunk_index + 1}/"
            f"{self.incoming_manifest.total_chunks} ({bytes_written} plaintext bytes)."
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
        print("[Alice] ENCRYPTED FILE RECEIVED SUCCESSFULLY.")
        print(f"[Alice] Saved file: {final_path}")
        print(f"[Alice] Verified size: {final_path.stat().st_size} bytes")
        print(f"[Alice] Verified SHA-256: {received_hash}")
        print("[Alice] File integrity verification: PASS")

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

        if not self.reply_file_sent:
            reply_file = self._create_demo_reply_file()
            print("\n[Alice] Starting encrypted reply-file transfer to Bob...")
            self.send_file(reply_file)
            self.reply_file_sent = True

    def send_file(self, file_path: str | Path) -> None:
        self._require_secure_session()
        connection = self._require_connection()
        manifest = self.file_manager.prepare_manifest(file_path)

        manifest_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {"action": "MANIFEST", "manifest": manifest.to_payload()},
            sender="Alice",
        )
        NetworkProtocol.send_packet(connection, manifest_packet)

        print(f"[Alice] Sending encrypted file: {manifest.file_name}")
        print(f"[Alice] File size: {manifest.file_size} bytes")
        print(f"[Alice] Total chunks: {manifest.total_chunks}")
        print(f"[Alice] Source SHA-256: {manifest.sha256_hex}")

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
            NetworkProtocol.send_packet(connection, packet)
            print(
                f"[Alice] Sent encrypted chunk {chunk.chunk_index + 1}/"
                f"{manifest.total_chunks}."
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
        NetworkProtocol.send_packet(connection, complete_packet)

        response = NetworkProtocol.receive_packet(connection)
        response_type = NetworkProtocol.get_message_type(response)
        if response_type == MessageType.ERROR:
            raise ProtocolError(response["payload"].get("message", "Bob rejected the file."))
        if response_type != MessageType.ACK:
            raise ProtocolError("Expected Bob's final file ACK.")

        ack = response["payload"]
        if ack.get("received_packet_id") != complete_packet["packet_id"]:
            raise ProtocolError("Bob acknowledged the wrong FILE COMPLETE packet.")
        if not ack.get("file_verified"):
            raise ProtocolError("Bob did not confirm file verification.")
        if ack.get("sha256") != manifest.sha256_hex:
            raise ProtocolError("Bob reported a different file SHA-256 value.")

        print("[Alice] Bob authenticated and verified Alice's encrypted file.")
        print("[Alice] ALICE-TO-BOB ENCRYPTED FILE TRANSFER: PASS")

    def _create_demo_reply_file(self) -> Path:
        directory = Path("stage11_tcp_demo")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "alice_to_bob_secure_reply.txt"
        content = (
            "Alice secure file-transfer confirmation.\n"
            "This file travelled from Alice to Bob using AES-256-GCM.\n"
            "Every chunk used a fresh nonce and an authentication tag.\n"
        ) * 900
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Control, helpers and shutdown
    # ------------------------------------------------------------------

    def _send_ack(self, packet_id: str, message: str, extra: Optional[dict] = None) -> None:
        payload = {"message": message, "received_packet_id": packet_id}
        if extra:
            payload.update(extra)
        packet = NetworkProtocol.create_packet(MessageType.ACK, payload, sender="Alice")
        NetworkProtocol.send_packet(self._require_connection(), packet)

    def _send_error(self, packet_id: str, message: str) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ERROR,
            {"message": message, "received_packet_id": packet_id},
            sender="Alice",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)

    def _chat_aad(self, sender: str, sequence: int) -> bytes:
        self._require_secure_session()
        return f"CHAT|{self.session_id}|{sender}|{sequence}".encode("utf-8")

    def _require_secure_session(self) -> None:
        if (
            self.state != AliceServerState.SECURE_SESSION_READY
            or self.session_key is None
            or self.session_id is None
        ):
            raise RuntimeError("Secure session is not ready.")

    def _require_connection(self) -> socket.socket:
        if self.client_socket is None or self.client_socket.fileno() < 0:
            raise RuntimeError("Bob is not connected.")
        return self.client_socket

    def shutdown(self) -> None:
        if self.incoming_assembler is not None:
            self.incoming_assembler.abort()
            self.incoming_assembler = None
            self.incoming_manifest = None

        if self.client_socket is not None:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.client_socket.close()
            self.client_socket = None

        if self.server_socket is not None:
            self.server_socket.close()
            self.server_socket = None

        self.session_key = None
        self.session_id = None
        if self.state != AliceServerState.STOPPED:
            self._set_state(AliceServerState.STOPPED)
        print("[Alice] Session-key reference cleared.")
        print("[Alice] Server stopped safely.")

    def _set_state(self, state: AliceServerState) -> None:
        self.state = state
        print(f"[Alice] Server state: {state.value}")

    @staticmethod
    def _fingerprint(value: bytes) -> str:
        digest = sha256(value).hexdigest().upper()
        return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))

    @staticmethod
    def _validate_uuid(value: str, field: str) -> None:
        try:
            uuid.UUID(value)
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError(f"{field} is not a valid UUID.") from error

    @staticmethod
    def _print_banner() -> None:
        print("=" * 96)
        print("STAGE 11B: ALICE TWO-WAY AES-256-GCM FILE-TRANSFER SERVER")
        print("=" * 96)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Alice's Stage 11B server.")
    parser.add_argument("--host", default=AliceServer.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=AliceServer.DEFAULT_PORT)
    parser.add_argument("--manual-chat-reply", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    AliceServer(
        host=arguments.host,
        port=arguments.port,
        automatic_chat_reply=not arguments.manual_chat_reply,
    ).run()


if __name__ == "__main__":
    main()
