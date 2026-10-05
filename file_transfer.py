"""
Secure encrypted file-transfer services.

This module provides:

1. File metadata preparation.
2. Whole-file SHA-256 calculation.
3. File division into fixed-size chunks.
4. AES-256-GCM encryption of each chunk.
5. Fresh nonce generation for every chunk.
6. Authentication of file metadata using associated data.
7. Ordered file reconstruction.
8. Final file-size and SHA-256 verification.
9. Safe received-filename handling.

TCP packet integration is added in Stage 11B.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterator, Optional

from crypto_manager import (
    AESGCMEncryptedData,
    CryptoManager,
)
from network_protocol import NetworkProtocol, ProtocolError


@dataclass(frozen=True)
class FileManifest:
    """
    Describe a file before encrypted transfer.

    Attributes:
        transfer_id: Unique identifier for one file transfer.
        file_name: Sanitised base filename.
        file_size: Original plaintext file size in bytes.
        chunk_size: Maximum plaintext bytes in one chunk.
        total_chunks: Number of encrypted chunks.
        sha256_hex: SHA-256 digest of the complete plaintext file.
    """

    transfer_id: str
    file_name: str
    file_size: int
    chunk_size: int
    total_chunks: int
    sha256_hex: str

    def to_payload(self) -> dict:
        """Convert the manifest into a JSON-compatible payload."""

        return {
            "transfer_id": self.transfer_id,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "sha256": self.sha256_hex,
        }

    @classmethod
    def from_payload(
        cls,
        payload: dict,
    ) -> "FileManifest":
        """
        Create a manifest from a received network payload.

        Raises:
            ProtocolError: If required fields are missing or invalid.
        """

        if not isinstance(payload, dict):
            raise ProtocolError(
                "File manifest payload must be a dictionary."
            )

        required_fields = {
            "transfer_id",
            "file_name",
            "file_size",
            "chunk_size",
            "total_chunks",
            "sha256",
        }

        missing_fields = required_fields - set(payload.keys())

        if missing_fields:
            raise ProtocolError(
                "File manifest is missing: "
                + ", ".join(sorted(missing_fields))
            )

        try:
            manifest = cls(
                transfer_id=str(payload["transfer_id"]),
                file_name=str(payload["file_name"]),
                file_size=int(payload["file_size"]),
                chunk_size=int(payload["chunk_size"]),
                total_chunks=int(payload["total_chunks"]),
                sha256_hex=str(payload["sha256"]),
            )

        except (TypeError, ValueError) as error:
            raise ProtocolError(
                "File manifest contains invalid values."
            ) from error

        return manifest


@dataclass(frozen=True)
class EncryptedFileChunk:
    """
    Store one AES-GCM encrypted file chunk.

    Attributes:
        transfer_id: File-transfer identifier.
        chunk_index: Zero-based chunk number.
        plaintext_size: Original size of this chunk.
        nonce: AES-GCM nonce.
        ciphertext: Encrypted chunk data.
        tag: AES-GCM authentication tag.
    """

    transfer_id: str
    chunk_index: int
    plaintext_size: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_payload(self) -> dict:
        """Convert the encrypted chunk into a network payload."""

        return {
            "transfer_id": self.transfer_id,
            "chunk_index": self.chunk_index,
            "plaintext_size": self.plaintext_size,
            "nonce": NetworkProtocol.encode_bytes(
                self.nonce
            ),
            "ciphertext": NetworkProtocol.encode_bytes(
                self.ciphertext
            ),
            "tag": NetworkProtocol.encode_bytes(
                self.tag
            ),
        }

    @classmethod
    def from_payload(
        cls,
        payload: dict,
    ) -> "EncryptedFileChunk":
        """
        Decode one encrypted chunk from a network payload.
        """

        if not isinstance(payload, dict):
            raise ProtocolError(
                "File-chunk payload must be a dictionary."
            )

        required_fields = {
            "transfer_id",
            "chunk_index",
            "plaintext_size",
            "nonce",
            "ciphertext",
            "tag",
        }

        missing_fields = required_fields - set(payload.keys())

        if missing_fields:
            raise ProtocolError(
                "Encrypted file chunk is missing: "
                + ", ".join(sorted(missing_fields))
            )

        try:
            return cls(
                transfer_id=str(payload["transfer_id"]),
                chunk_index=int(payload["chunk_index"]),
                plaintext_size=int(
                    payload["plaintext_size"]
                ),
                nonce=NetworkProtocol.decode_bytes(
                    payload["nonce"]
                ),
                ciphertext=NetworkProtocol.decode_bytes(
                    payload["ciphertext"]
                ),
                tag=NetworkProtocol.decode_bytes(
                    payload["tag"]
                ),
            )

        except (TypeError, ValueError) as error:
            raise ProtocolError(
                "Encrypted file chunk contains invalid values."
            ) from error


class FileTransferManager:
    """
    Prepare, encrypt, decrypt and verify file transfers.
    """

    DEFAULT_CHUNK_SIZE = 64 * 1024
    MAX_CHUNK_SIZE = 1024 * 1024
    MAX_FILE_SIZE = 100 * 1024 * 1024

    SHA256_PATTERN = re.compile(
        r"^[0-9a-fA-F]{64}$"
    )

    def __init__(
        self,
        crypto_manager: Optional[CryptoManager] = None,
    ) -> None:
        """Create the file-transfer manager."""

        self.crypto_manager = (
            crypto_manager or CryptoManager()
        )

    def prepare_manifest(
        self,
        file_path: str | Path,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        transfer_id: Optional[str] = None,
    ) -> FileManifest:
        """
        Inspect a file and prepare its transfer manifest.

        Args:
            file_path: Existing source file.
            chunk_size: Maximum plaintext bytes per chunk.
            transfer_id: Optional existing UUID.

        Returns:
            Validated FileManifest.
        """

        source_path = Path(file_path).expanduser().resolve()

        if not source_path.exists():
            raise FileNotFoundError(
                f"Source file does not exist: {source_path}"
            )

        if not source_path.is_file():
            raise ValueError(
                "The selected source path is not a file."
            )

        self._validate_chunk_size(chunk_size)

        file_size = source_path.stat().st_size

        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                "The selected file exceeds the maximum "
                f"size of {self.MAX_FILE_SIZE} bytes."
            )

        if transfer_id is None:
            transfer_id = str(uuid.uuid4())

        self._validate_uuid(
            transfer_id,
            "File-transfer identifier",
        )

        total_chunks = max(
            1,
            math.ceil(file_size / chunk_size),
        )

        manifest = FileManifest(
            transfer_id=transfer_id,
            file_name=self.sanitise_filename(
                source_path.name
            ),
            file_size=file_size,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            sha256_hex=self.calculate_file_sha256(
                source_path
            ),
        )

        self.validate_manifest(manifest)

        return manifest

    def validate_manifest(
        self,
        manifest: FileManifest,
    ) -> None:
        """Validate received or locally created metadata."""

        if not isinstance(manifest, FileManifest):
            raise TypeError(
                "manifest must be a FileManifest."
            )

        self._validate_uuid(
            manifest.transfer_id,
            "File-transfer identifier",
        )

        safe_name = self.sanitise_filename(
            manifest.file_name
        )

        if manifest.file_name != safe_name:
            raise ValueError(
                "The file manifest contains an unsafe filename."
            )

        if manifest.file_size < 0:
            raise ValueError(
                "File size cannot be negative."
            )

        if manifest.file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                "File exceeds the maximum permitted size."
            )

        self._validate_chunk_size(
            manifest.chunk_size
        )

        expected_chunks = max(
            1,
            math.ceil(
                manifest.file_size
                / manifest.chunk_size
            ),
        )

        if manifest.total_chunks != expected_chunks:
            raise ValueError(
                "Manifest total-chunk count is incorrect."
            )

        if not self.SHA256_PATTERN.fullmatch(
            manifest.sha256_hex
        ):
            raise ValueError(
                "Manifest SHA-256 value is invalid."
            )

    def iter_encrypted_chunks(
        self,
        file_path: str | Path,
        aes_key: bytes,
        session_id: str,
        sender: str,
        manifest: Optional[FileManifest] = None,
    ) -> Iterator[EncryptedFileChunk]:
        """
        Read and encrypt a file one chunk at a time.

        A new AES-GCM nonce is generated by CryptoManager for every
        encryption operation.
        """

        source_path = Path(file_path).expanduser().resolve()

        if manifest is None:
            manifest = self.prepare_manifest(
                source_path
            )

        self.validate_manifest(manifest)

        if (
            self.sanitise_filename(source_path.name)
            != manifest.file_name
        ):
            raise ValueError(
                "Source filename does not match the manifest."
            )

        actual_size = source_path.stat().st_size

        if actual_size != manifest.file_size:
            raise ValueError(
                "Source file size changed after manifest creation."
            )

        self._validate_uuid(
            session_id,
            "Session identifier",
        )
        self._validate_sender(sender)

        with source_path.open("rb") as source_file:
            for chunk_index in range(
                manifest.total_chunks
            ):
                plaintext = source_file.read(
                    manifest.chunk_size
                )

                expected_size = (
                    self.expected_chunk_plaintext_size(
                        manifest,
                        chunk_index,
                    )
                )

                if len(plaintext) != expected_size:
                    raise RuntimeError(
                        "Source file changed while it "
                        "was being encrypted."
                    )

                associated_data = (
                    self.build_chunk_associated_data(
                        manifest=manifest,
                        session_id=session_id,
                        sender=sender,
                        chunk_index=chunk_index,
                    )
                )

                encrypted = (
                    self.crypto_manager.encrypt_data(
                        plaintext=plaintext,
                        aes_key=aes_key,
                        associated_data=associated_data,
                    )
                )

                yield EncryptedFileChunk(
                    transfer_id=manifest.transfer_id,
                    chunk_index=chunk_index,
                    plaintext_size=len(plaintext),
                    nonce=encrypted.nonce,
                    ciphertext=encrypted.ciphertext,
                    tag=encrypted.tag,
                )

            if source_file.read(1):
                raise RuntimeError(
                    "Source file increased in size during transfer."
                )

    def decrypt_chunk(
        self,
        encrypted_chunk: EncryptedFileChunk,
        manifest: FileManifest,
        aes_key: bytes,
        session_id: str,
        sender: str,
    ) -> bytes:
        """
        Authenticate and decrypt one file chunk.
        """

        self.validate_manifest(manifest)

        if not isinstance(
            encrypted_chunk,
            EncryptedFileChunk,
        ):
            raise TypeError(
                "encrypted_chunk must be EncryptedFileChunk."
            )

        if (
            encrypted_chunk.transfer_id
            != manifest.transfer_id
        ):
            raise ValueError(
                "Encrypted chunk belongs to another transfer."
            )

        if not (
            0
            <= encrypted_chunk.chunk_index
            < manifest.total_chunks
        ):
            raise ValueError(
                "Encrypted chunk index is out of range."
            )

        expected_size = (
            self.expected_chunk_plaintext_size(
                manifest,
                encrypted_chunk.chunk_index,
            )
        )

        if (
            encrypted_chunk.plaintext_size
            != expected_size
        ):
            raise ValueError(
                "Encrypted chunk plaintext size is incorrect."
            )

        self._validate_uuid(
            session_id,
            "Session identifier",
        )
        self._validate_sender(sender)

        associated_data = (
            self.build_chunk_associated_data(
                manifest=manifest,
                session_id=session_id,
                sender=sender,
                chunk_index=(
                    encrypted_chunk.chunk_index
                ),
            )
        )

        encrypted_data = AESGCMEncryptedData(
            nonce=encrypted_chunk.nonce,
            ciphertext=encrypted_chunk.ciphertext,
            tag=encrypted_chunk.tag,
        )

        plaintext = self.crypto_manager.decrypt_data(
            encrypted_data=encrypted_data,
            aes_key=aes_key,
            associated_data=associated_data,
        )

        if len(plaintext) != expected_size:
            raise ValueError(
                "Decrypted chunk size does not match "
                "the authenticated metadata."
            )

        return plaintext

    def build_chunk_associated_data(
        self,
        manifest: FileManifest,
        session_id: str,
        sender: str,
        chunk_index: int,
    ) -> bytes:
        """
        Construct authenticated metadata for one file chunk.

        The metadata is authenticated but not encrypted.
        """

        return (
            f"FILE|{session_id}|"
            f"{manifest.transfer_id}|"
            f"{sender}|"
            f"{manifest.file_name}|"
            f"{chunk_index}|"
            f"{manifest.total_chunks}|"
            f"{manifest.file_size}|"
            f"{manifest.sha256_hex}"
        ).encode("utf-8")

    def expected_chunk_plaintext_size(
        self,
        manifest: FileManifest,
        chunk_index: int,
    ) -> int:
        """Calculate the expected plaintext size of one chunk."""

        if not (
            0 <= chunk_index < manifest.total_chunks
        ):
            raise ValueError(
                "Chunk index is out of range."
            )

        if chunk_index < manifest.total_chunks - 1:
            return manifest.chunk_size

        consumed_before_last = (
            manifest.chunk_size
            * (manifest.total_chunks - 1)
        )

        return (
            manifest.file_size
            - consumed_before_last
        )

    @staticmethod
    def calculate_file_sha256(
        file_path: str | Path,
        read_size: int = 1024 * 1024,
    ) -> str:
        """Calculate a file's SHA-256 digest without loading it all."""

        path = Path(file_path).expanduser().resolve()

        if not path.is_file():
            raise FileNotFoundError(
                f"Cannot hash missing file: {path}"
            )

        digest = sha256()

        with path.open("rb") as file_handle:
            while True:
                data = file_handle.read(read_size)

                if not data:
                    break

                digest.update(data)

        return digest.hexdigest()

    @staticmethod
    def calculate_bytes_sha256(
        data: bytes,
    ) -> str:
        """Calculate a SHA-256 digest for bytes."""

        if not isinstance(data, bytes):
            raise TypeError(
                "SHA-256 input must be bytes."
            )

        return sha256(data).hexdigest()

    @staticmethod
    def sanitise_filename(
        file_name: str,
    ) -> str:
        """
        Remove path components and unsafe filename characters.

        The receiver never trusts a remotely supplied path.
        """

        if not isinstance(file_name, str):
            raise TypeError(
                "Filename must be a string."
            )

        normalised = file_name.replace(
            "\\",
            "/",
        )

        base_name = normalised.rsplit(
            "/",
            1,
        )[-1]

        cleaned = "".join(
            character
            if (
                character.isalnum()
                or character in "._- "
            )
            else "_"
            for character in base_name
        )

        cleaned = cleaned.strip(" .")

        if cleaned in {"", ".", ".."}:
            cleaned = "received_file"

        return cleaned[:150]

    @staticmethod
    def _validate_uuid(
        value: str,
        field_name: str,
    ) -> None:
        """Validate a UUID string."""

        try:
            uuid.UUID(str(value))

        except (
            ValueError,
            TypeError,
            AttributeError,
        ) as error:
            raise ValueError(
                f"{field_name} must be a valid UUID."
            ) from error

    @classmethod
    def _validate_chunk_size(
        cls,
        chunk_size: int,
    ) -> None:
        """Validate plaintext chunk size."""

        if not isinstance(chunk_size, int):
            raise TypeError(
                "Chunk size must be an integer."
            )

        if not 1 <= chunk_size <= cls.MAX_CHUNK_SIZE:
            raise ValueError(
                "Chunk size must be between 1 and "
                f"{cls.MAX_CHUNK_SIZE} bytes."
            )

    @staticmethod
    def _validate_sender(
        sender: str,
    ) -> None:
        """Validate the sender value used in associated data."""

        if not isinstance(sender, str):
            raise TypeError(
                "File sender must be a string."
            )

        if (
            not sender.strip()
            or "|" in sender
            or len(sender) > 100
        ):
            raise ValueError(
                "File sender is invalid."
            )


class IncomingFileAssembler:
    """
    Reconstruct an authenticated incoming file safely.

    Data is written to a temporary `.part` file. It is renamed only
    after the final size and SHA-256 digest have been verified.
    """

    def __init__(
        self,
        manager: FileTransferManager,
        manifest: FileManifest,
        destination_directory: str | Path,
    ) -> None:
        """Prepare a new incoming file transfer."""

        manager.validate_manifest(manifest)

        self.manager = manager
        self.manifest = manifest

        self.destination_directory = Path(
            destination_directory
        ).expanduser().resolve()

        self.destination_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        safe_name = manager.sanitise_filename(
            manifest.file_name
        )

        transfer_prefix = (
            manifest.transfer_id
            .replace("-", "")[:12]
        )

        requested_final_path = (
            self.destination_directory
            / f"{transfer_prefix}_{safe_name}"
        )

        self.final_path = (
            self._select_available_path(
                requested_final_path
            )
        )

        self.temporary_path = self.final_path.with_name(
            self.final_path.name + ".part"
        )

        self.expected_chunk_index = 0
        self.bytes_written = 0
        self._sha256 = sha256()
        self._closed = False
        self._finalised = False

        self._file_handle = self.temporary_path.open(
            "xb"
        )

    def add_chunk(
        self,
        encrypted_chunk: EncryptedFileChunk,
        aes_key: bytes,
        session_id: str,
        sender: str,
    ) -> int:
        """
        Authenticate, decrypt and write the next expected chunk.

        Returns:
            Number of plaintext bytes written.
        """

        if self._closed:
            raise RuntimeError(
                "Incoming transfer is already closed."
            )

        if self._finalised:
            raise RuntimeError(
                "Incoming transfer is already finalised."
            )

        if (
            encrypted_chunk.chunk_index
            != self.expected_chunk_index
        ):
            raise ValueError(
                "Unexpected file-chunk order. "
                f"Expected {self.expected_chunk_index}, "
                f"received {encrypted_chunk.chunk_index}."
            )

        plaintext = self.manager.decrypt_chunk(
            encrypted_chunk=encrypted_chunk,
            manifest=self.manifest,
            aes_key=aes_key,
            session_id=session_id,
            sender=sender,
        )

        self._file_handle.write(plaintext)
        self._sha256.update(plaintext)

        self.bytes_written += len(plaintext)
        self.expected_chunk_index += 1

        return len(plaintext)

    def finalise(self) -> Path:
        """
        Verify and publish the completed received file.

        Returns:
            Final verified file path.
        """

        if self._closed:
            raise RuntimeError(
                "Incoming transfer is already closed."
            )

        if (
            self.expected_chunk_index
            != self.manifest.total_chunks
        ):
            raise ValueError(
                "Not all expected file chunks were received."
            )

        if (
            self.bytes_written
            != self.manifest.file_size
        ):
            raise ValueError(
                "Received file size does not match "
                "the manifest."
            )

        calculated_hash = (
            self._sha256.hexdigest()
        )

        if (
            calculated_hash.lower()
            != self.manifest.sha256_hex.lower()
        ):
            self.abort()

            raise ValueError(
                "Received file SHA-256 verification failed."
            )

        self._file_handle.flush()
        self._file_handle.close()

        self._closed = True
        self._finalised = True

        self.temporary_path.replace(
            self.final_path
        )

        return self.final_path

    def abort(self) -> None:
        """Close and remove an incomplete temporary file."""

        if not self._closed:
            try:
                self._file_handle.close()
            except OSError:
                pass

            self._closed = True

        try:
            if self.temporary_path.exists():
                self.temporary_path.unlink()
        except OSError:
            pass

    @staticmethod
    def _select_available_path(
        requested_path: Path,
    ) -> Path:
        """Avoid overwriting an existing received file."""

        if (
            not requested_path.exists()
            and not requested_path.with_name(
                requested_path.name + ".part"
            ).exists()
        ):
            return requested_path

        counter = 1

        while True:
            candidate = requested_path.with_name(
                f"{requested_path.stem}_{counter}"
                f"{requested_path.suffix}"
            )

            temporary_candidate = candidate.with_name(
                candidate.name + ".part"
            )

            if (
                not candidate.exists()
                and not temporary_candidate.exists()
            ):
                return candidate

            counter += 1