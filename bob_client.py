"""
Stage 11B Bob client: RSA-OAEP key exchange, AES-256-GCM chat,
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
from network_protocol import MessageType, NetworkProtocol, ProtocolError


class BobClientState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    TCP_CONNECTED = "TCP_CONNECTED"
    PUBLIC_KEY_RECEIVED = "PUBLIC_KEY_RECEIVED"
    SECURE_SESSION_READY = "SECURE_SESSION_READY"
    DISCONNECTING = "DISCONNECTING"
    STOPPED = "STOPPED"


class BobClient:
    """Bob's secure TCP client."""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 5000

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        received_directory: str | Path = "received_files/bob",
    ) -> None:
        self.host = host.strip()
        self.port = port
        self.received_directory = Path(received_directory)

        self.crypto_manager = CryptoManager()
        self.file_manager = FileTransferManager(self.crypto_manager)

        self.connection: Optional[socket.socket] = None
        self.session_key: Optional[bytes] = None
        self.session_id: Optional[str] = None
        self.public_key_packet_id: Optional[str] = None

        self.chat_send_sequence = 0
        self.expected_alice_chat_sequence = 1
        self.state = BobClientState.DISCONNECTED

    def run_demo(self) -> None:
        self._print_banner()
        try:
            self.connect()
            public_key_packet = self.receive_public_key()
            self.send_public_key_ack(public_key_packet)
            self.establish_secure_session()

            self.send_chat_message(
                "Hello Alice. Bob is testing chat before encrypted file transfer."
            )
            self.receive_chat_message()

            source_file = self._create_demo_source_file()
            print("\n[Bob] Starting Bob-to-Alice encrypted file transfer...")
            self.send_file(source_file)

            print("\n[Bob] Waiting for Alice's encrypted reply file...")
            received_reply = self.receive_file(expected_sender="Alice")
            print(f"[Bob] Alice's verified reply file: {received_reply}")

            self.send_status("Stage 11B two-way encrypted file transfer passed.")
            self.disconnect("Stage 11B demonstration is complete.")

            print("\n[Bob] ALL STAGE 11B TCP FILE-TRANSFER TESTS PASSED SUCCESSFULLY.")
            print("[Bob] Bob-to-Alice encrypted file transfer: PASS")
            print("[Bob] Alice-to-Bob encrypted file transfer: PASS")
            print("[Bob] AES-GCM authentication and SHA-256 verification: PASS")
            print("[Bob] The project is ready for Stage 12: Tkinter GUI development.")
        except ConnectionRefusedError:
            print("[Bob] Connection refused. Start Alice first.")
        except (
            OSError,
            ProtocolError,
            ConnectionError,
            RuntimeError,
            ValueError,
            TypeError,
        ) as error:
            print(f"\n[Bob] Application error: {error}")
        finally:
            self.close()

    def run_interactive(self) -> None:
        self._print_banner()
        try:
            self.connect()
            public_key_packet = self.receive_public_key()
            self.send_public_key_ack(public_key_packet)
            self.establish_secure_session()

            print("\n[Bob] Commands: chat, sendfile, receivefile, status, disconnect")
            while self.connection is not None:
                command = input("Bob command: ").strip().lower()
                if command == "chat":
                    message = input("Encrypted message: ").strip()
                    self.send_chat_message(message)
                    self.receive_chat_message()
                elif command == "sendfile":
                    path = input("Path of file to send: ").strip().strip('"')
                    self.send_file(path)
                elif command == "receivefile":
                    path = self.receive_file(expected_sender="Alice")
                    print(f"[Bob] Verified received file: {path}")
                elif command == "status":
                    self.send_status("Bob's Stage 11B session is active.")
                elif command in {"disconnect", "quit", "exit"}:
                    self.disconnect("Bob ended the interactive session.")
                    break
                else:
                    print("[Bob] Use chat, sendfile, receivefile, status or disconnect.")
        finally:
            self.close()

    # ------------------------------------------------------------------
    # Connection and key exchange
    # ------------------------------------------------------------------

    def connect(self) -> None:
        if not self.host:
            raise ValueError("Host cannot be empty.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        self._set_state(BobClientState.CONNECTING)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.connect((self.host, self.port))
        except OSError:
            connection.close()
            raise
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection = connection
        self._set_state(BobClientState.TCP_CONNECTED)
        print(f"[Bob] Connected to Alice at {self.host}:{self.port}")

    def receive_public_key(self) -> dict:
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

        self.public_key_packet_id = packet["packet_id"]
        self._set_state(BobClientState.PUBLIC_KEY_RECEIVED)
        print("[Bob] Alice's RSA-2048 public key verified: PASS")
        print("[Bob] Alice's private key present on Bob: False")
        return packet

    def send_public_key_ack(self, public_key_packet: dict) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ACK,
            {
                "message": "Alice's RSA public key was received and verified by Bob.",
                "received_packet_id": public_key_packet["packet_id"],
                "public_key_fingerprint": self.crypto_manager.get_public_key_fingerprint(),
            },
            sender="Bob",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)

    def establish_secure_session(self) -> None:
        connection = self._require_connection()
        self.session_key = self.crypto_manager.generate_aes_key()
        self.session_id = str(uuid.uuid4())
        fingerprint = self._fingerprint(self.session_key)
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
        NetworkProtocol.send_packet(connection, packet)

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

        self._set_state(BobClientState.SECURE_SESSION_READY)
        print("[Bob] SECURE AES-256 SESSION ESTABLISHED SUCCESSFULLY.")
        print(f"[Bob] Session ID: {self.session_id}")
        print(f"[Bob] RSA-OAEP ciphertext size: {len(encrypted_key)} bytes")

    # ------------------------------------------------------------------
    # Chat retained from Stage 10
    # ------------------------------------------------------------------

    def send_chat_message(self, plaintext: str) -> None:
        self._require_secure_session()
        if not plaintext.strip():
            raise ValueError("Chat message cannot be empty.")
        self.chat_send_sequence += 1
        encrypted = self.crypto_manager.encrypt_text(
            plaintext=plaintext.strip(),
            aes_key=self.session_key,
            associated_data=self._chat_aad("Bob", self.chat_send_sequence),
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
            sender="Bob",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)
        print(f"[Bob] Encrypted CHAT sequence {self.chat_send_sequence} sent.")

    def receive_chat_message(self) -> str:
        packet = NetworkProtocol.receive_packet(self._require_connection())
        if NetworkProtocol.get_message_type(packet) != MessageType.CHAT:
            raise ProtocolError("Expected Alice's encrypted CHAT reply.")
        payload = packet["payload"]
        sequence = int(payload["sequence"])
        if sequence != self.expected_alice_chat_sequence:
            raise ProtocolError("Unexpected Alice CHAT sequence.")
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
        print("[Bob] Alice CHAT AES-GCM authentication: PASS")
        print(f"[Bob] Decrypted message from Alice: {plaintext}")
        return plaintext

    # ------------------------------------------------------------------
    # Two-way encrypted file transfer
    # ------------------------------------------------------------------

    def send_file(self, file_path: str | Path) -> None:
        self._require_secure_session()
        connection = self._require_connection()
        manifest = self.file_manager.prepare_manifest(file_path)

        manifest_packet = NetworkProtocol.create_packet(
            MessageType.FILE,
            {"action": "MANIFEST", "manifest": manifest.to_payload()},
            sender="Bob",
        )
        NetworkProtocol.send_packet(connection, manifest_packet)

        print(f"[Bob] Sending encrypted file: {manifest.file_name}")
        print(f"[Bob] File size: {manifest.file_size} bytes")
        print(f"[Bob] Total chunks: {manifest.total_chunks}")
        print(f"[Bob] Source SHA-256: {manifest.sha256_hex}")

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
            NetworkProtocol.send_packet(connection, packet)
            print(f"[Bob] Sent encrypted chunk {chunk.chunk_index + 1}/{manifest.total_chunks}.")

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
        NetworkProtocol.send_packet(connection, complete_packet)

        response = NetworkProtocol.receive_packet(connection)
        response_type = NetworkProtocol.get_message_type(response)
        if response_type == MessageType.ERROR:
            raise ProtocolError(response["payload"].get("message", "Alice rejected the file."))
        if response_type != MessageType.ACK:
            raise ProtocolError("Expected Alice's final file ACK.")

        ack = response["payload"]
        if ack.get("received_packet_id") != complete_packet["packet_id"]:
            raise ProtocolError("Alice acknowledged the wrong FILE COMPLETE packet.")
        if not ack.get("file_verified"):
            raise ProtocolError("Alice did not confirm file verification.")
        if ack.get("sha256") != manifest.sha256_hex:
            raise ProtocolError("Alice reported a different file SHA-256 value.")

        print("[Bob] Alice authenticated and verified Bob's encrypted file.")
        print("[Bob] BOB-TO-ALICE ENCRYPTED FILE TRANSFER: PASS")

    def receive_file(self, expected_sender: str) -> Path:
        self._require_secure_session()
        connection = self._require_connection()
        manifest: Optional[FileManifest] = None
        assembler: Optional[IncomingFileAssembler] = None

        try:
            while True:
                packet = NetworkProtocol.receive_packet(connection)
                message_type = NetworkProtocol.get_message_type(packet)
                if message_type == MessageType.ERROR:
                    raise ProtocolError(packet["payload"].get("message", "Alice reported an error."))
                if message_type != MessageType.FILE:
                    raise ProtocolError(f"Expected FILE packet, received {message_type.value}.")
                if packet.get("sender") != expected_sender:
                    raise ProtocolError("Unexpected FILE sender.")

                payload = packet["payload"]
                action = payload.get("action")

                if action == "MANIFEST":
                    if assembler is not None:
                        raise ProtocolError("A second FILE manifest arrived unexpectedly.")
                    manifest = FileManifest.from_payload(payload["manifest"])
                    self.file_manager.validate_manifest(manifest)
                    assembler = IncomingFileAssembler(
                        self.file_manager,
                        manifest,
                        self.received_directory,
                    )
                    print("[Bob] Alice FILE manifest accepted.")
                    print(f"[Bob] Incoming filename: {manifest.file_name}")
                    print(f"[Bob] Incoming size: {manifest.file_size} bytes")
                    print(f"[Bob] Total chunks: {manifest.total_chunks}")
                    print(f"[Bob] Sender SHA-256: {manifest.sha256_hex}")

                elif action == "CHUNK":
                    if manifest is None or assembler is None:
                        raise ProtocolError("FILE chunk arrived before the manifest.")
                    chunk = EncryptedFileChunk.from_payload(payload["chunk"])
                    written = assembler.add_chunk(
                        encrypted_chunk=chunk,
                        aes_key=self.session_key,
                        session_id=self.session_id,
                        sender=expected_sender,
                    )
                    print(
                        f"[Bob] Authenticated FILE chunk {chunk.chunk_index + 1}/"
                        f"{manifest.total_chunks} ({written} plaintext bytes)."
                    )

                elif action == "COMPLETE":
                    if manifest is None or assembler is None:
                        raise ProtocolError("FILE COMPLETE arrived without a manifest.")
                    if payload.get("transfer_id") != manifest.transfer_id:
                        raise ProtocolError("FILE COMPLETE transfer ID does not match.")

                    final_path = assembler.finalise()
                    verified_hash = self.file_manager.calculate_file_sha256(final_path)
                    self._send_file_ack(packet["packet_id"], manifest, verified_hash)
                    print("[Bob] ENCRYPTED FILE RECEIVED SUCCESSFULLY.")
                    print(f"[Bob] Saved file: {final_path}")
                    print(f"[Bob] Verified size: {final_path.stat().st_size} bytes")
                    print(f"[Bob] Verified SHA-256: {verified_hash}")
                    print("[Bob] File integrity verification: PASS")
                    print("[Bob] ALICE-TO-BOB ENCRYPTED FILE TRANSFER: PASS")
                    return final_path

                else:
                    raise ProtocolError(f"Unsupported FILE action: {action!r}")
        except Exception:
            if assembler is not None:
                assembler.abort()
            raise

    def _send_file_ack(self, packet_id: str, manifest: FileManifest, verified_hash: str) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.ACK,
            {
                "message": "Bob authenticated, reconstructed and verified Alice's file.",
                "received_packet_id": packet_id,
                "transfer_id": manifest.transfer_id,
                "file_name": manifest.file_name,
                "file_size": manifest.file_size,
                "sha256": verified_hash,
                "file_verified": True,
            },
            sender="Bob",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)

    def _create_demo_source_file(self) -> Path:
        directory = Path("stage11_tcp_demo")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "bob_to_alice_secure_file.txt"
        content = (
            "ISC 6220 Stage 11B secure file transfer from Bob to Alice.\n"
            "The file is encrypted in chunks using AES-256-GCM.\n"
            "SHA-256 verifies the reconstructed plaintext file.\n"
        ) * 1200
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Status, disconnect and helpers
    # ------------------------------------------------------------------

    def send_status(self, message: str) -> None:
        packet = NetworkProtocol.create_packet(
            MessageType.STATUS,
            {"message": message, "secure_session": True, "stage": "11B"},
            sender="Bob",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)

    def disconnect(self, reason: str) -> None:
        self._set_state(BobClientState.DISCONNECTING)
        packet = NetworkProtocol.create_packet(
            MessageType.DISCONNECT,
            {"message": reason, "secure_session": self.session_key is not None},
            sender="Bob",
        )
        NetworkProtocol.send_packet(self._require_connection(), packet)
        response = NetworkProtocol.receive_packet(self._require_connection())
        if NetworkProtocol.get_message_type(response) != MessageType.ACK:
            raise ProtocolError("Expected Alice's disconnect ACK.")
        if response["payload"].get("received_packet_id") != packet["packet_id"]:
            raise ProtocolError("Alice acknowledged the wrong disconnect packet.")
        print("[Bob] Alice acknowledged the disconnect request.")
        self.close()

    def _chat_aad(self, sender: str, sequence: int) -> bytes:
        self._require_secure_session()
        return f"CHAT|{self.session_id}|{sender}|{sequence}".encode("utf-8")

    def _require_secure_session(self) -> None:
        if (
            self.state != BobClientState.SECURE_SESSION_READY
            or self.session_key is None
            or self.session_id is None
        ):
            raise RuntimeError("Secure session is not ready.")

    def _require_connection(self) -> socket.socket:
        if self.connection is None or self.connection.fileno() < 0:
            raise RuntimeError("Bob is not connected.")
        return self.connection

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            self.connection = None

        self.session_key = None
        self.session_id = None
        if self.state != BobClientState.STOPPED:
            self._set_state(BobClientState.STOPPED)
        print("[Bob] Session-key reference cleared.")
        print("[Bob] Client socket closed safely.")

    def _set_state(self, state: BobClientState) -> None:
        self.state = state
        print(f"[Bob] Client state: {state.value}")

    @staticmethod
    def _fingerprint(value: bytes) -> str:
        digest = sha256(value).hexdigest().upper()
        return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))

    @staticmethod
    def _print_banner() -> None:
        print("=" * 96)
        print("STAGE 11B: BOB TWO-WAY AES-256-GCM FILE-TRANSFER CLIENT")
        print("=" * 96)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Bob's Stage 11B client.")
    parser.add_argument("--host", default=BobClient.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=BobClient.DEFAULT_PORT)
    parser.add_argument("--demo", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    client = BobClient(arguments.host, arguments.port)
    if arguments.demo:
        client.run_demo()
    else:
        client.run_interactive()


if __name__ == "__main__":
    main()
