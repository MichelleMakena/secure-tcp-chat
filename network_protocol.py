"""
Length-prefixed TCP network protocol for the Secure TCP Chat Application.

The protocol performs:

1. Structured JSON packet creation.
2. Four-byte length-prefix framing.
3. Exact TCP byte reception.
4. Packet validation.
5. Binary-to-Base64 conversion.
6. Packet-size protection.
7. Graceful connection-closure detection.

TCP is a stream protocol and does not preserve application-message
boundaries. The four-byte length header allows the receiver to
reconstruct complete packets.
"""

from __future__ import annotations

import base64
import binascii
import json
import socket
import struct
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MessageType(str, Enum):
    """Supported application packet types."""

    PUBLIC_KEY = "PUBLIC_KEY"
    ENCRYPTED_AES_KEY = "ENCRYPTED_AES_KEY"
    CHAT = "CHAT"
    FILE = "FILE"
    STATUS = "STATUS"
    ERROR = "ERROR"
    DISCONNECT = "DISCONNECT"
    ACK = "ACK"


class ProtocolError(Exception):
    """Raised when a network packet violates the protocol."""


class ConnectionClosedError(ConnectionError):
    """Raised when the peer closes the TCP connection unexpectedly."""


class NetworkProtocol:
    """
    Encode, frame, transmit, receive and validate TCP packets.

    Packet format:

        4-byte unsigned big-endian length
        followed by
        UTF-8 JSON packet bytes
    """

    PROTOCOL_VERSION = 1

    HEADER_SIZE = 4

    # Individual encrypted files will later be transferred in chunks.
    # This protects the application from excessive packet allocation.
    MAX_PACKET_SIZE = 16 * 1024 * 1024

    @classmethod
    def create_packet(
        cls,
        message_type: MessageType | str,
        payload: dict[str, Any],
        sender: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a validated application packet.

        Args:
            message_type: A supported MessageType value.
            payload: JSON-compatible packet information.
            sender: Optional sender name, such as Alice or Bob.

        Returns:
            Newly created packet dictionary.

        Raises:
            ProtocolError: If an invalid type, sender or payload is used.
        """

        normalized_type = cls._normalize_message_type(
            message_type
        )

        if not isinstance(payload, dict):
            raise ProtocolError(
                "Packet payload must be a dictionary."
            )

        if sender is not None:
            if not isinstance(sender, str):
                raise ProtocolError(
                    "Packet sender must be a string or None."
                )

            sender = sender.strip()

            if not sender:
                raise ProtocolError(
                    "Packet sender cannot be empty."
                )

            if len(sender) > 100:
                raise ProtocolError(
                    "Packet sender is too long."
                )

        packet: dict[str, Any] = {
            "version": cls.PROTOCOL_VERSION,
            "packet_id": str(uuid.uuid4()),
            "type": normalized_type.value,
            "sender": sender,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "payload": payload,
        }

        cls.validate_packet(packet)

        return packet

    @classmethod
    def encode_packet(
        cls,
        packet: dict[str, Any],
    ) -> bytes:
        """
        Validate and encode a packet as compact UTF-8 JSON.

        Returns:
            JSON packet bytes without the four-byte header.
        """

        cls.validate_packet(packet)

        try:
            encoded = json.dumps(
                packet,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

        except (TypeError, ValueError) as error:
            raise ProtocolError(
                "Packet contains data that cannot be encoded as JSON."
            ) from error

        if not encoded:
            raise ProtocolError(
                "Encoded packet cannot be empty."
            )

        if len(encoded) > cls.MAX_PACKET_SIZE:
            raise ProtocolError(
                "Encoded packet exceeds the maximum permitted size."
            )

        return encoded

    @classmethod
    def decode_packet(
        cls,
        encoded_packet: bytes,
    ) -> dict[str, Any]:
        """
        Decode and validate UTF-8 JSON packet bytes.

        Args:
            encoded_packet: JSON body without a length header.

        Returns:
            Decoded packet dictionary.
        """

        if not isinstance(encoded_packet, bytes):
            raise TypeError(
                "Encoded packet must be supplied as bytes."
            )

        if not encoded_packet:
            raise ProtocolError(
                "Encoded packet cannot be empty."
            )

        if len(encoded_packet) > cls.MAX_PACKET_SIZE:
            raise ProtocolError(
                "Encoded packet exceeds the maximum permitted size."
            )

        try:
            decoded_text = encoded_packet.decode("utf-8")

        except UnicodeDecodeError as error:
            raise ProtocolError(
                "Packet is not valid UTF-8."
            ) from error

        try:
            packet = json.loads(decoded_text)

        except json.JSONDecodeError as error:
            raise ProtocolError(
                "Packet does not contain valid JSON."
            ) from error

        if not isinstance(packet, dict):
            raise ProtocolError(
                "Decoded packet must be a JSON object."
            )

        cls.validate_packet(packet)

        return packet

    @classmethod
    def frame_packet(
        cls,
        packet: dict[str, Any],
    ) -> bytes:
        """
        Add a four-byte network-order length header to a packet.

        Returns:
            Header and JSON body as one byte sequence.
        """

        body = cls.encode_packet(packet)

        header = struct.pack(
            ">I",
            len(body),
        )

        return header + body

    @classmethod
    def send_packet(
        cls,
        connection: socket.socket,
        packet: dict[str, Any],
    ) -> int:
        """
        Send one complete framed packet through a TCP socket.

        `sendall()` is used because one call to `send()` may transmit
        only part of the requested data.

        Returns:
            Total framed packet size in bytes.
        """

        cls._validate_socket(connection)

        framed_packet = cls.frame_packet(packet)

        try:
            connection.sendall(framed_packet)

        except OSError as error:
            raise ConnectionError(
                f"Failed to send TCP packet: {error}"
            ) from error

        return len(framed_packet)

    @classmethod
    def receive_packet(
        cls,
        connection: socket.socket,
    ) -> dict[str, Any]:
        """
        Receive one complete length-prefixed TCP packet.

        Steps:
            1. Receive exactly four header bytes.
            2. Decode the packet-body length.
            3. Receive exactly that many body bytes.
            4. Decode and validate the JSON packet.
        """

        cls._validate_socket(connection)

        header = cls.receive_exactly(
            connection,
            cls.HEADER_SIZE,
        )

        packet_size = struct.unpack(
            ">I",
            header,
        )[0]

        if packet_size == 0:
            raise ProtocolError(
                "TCP packet body cannot have zero length."
            )

        if packet_size > cls.MAX_PACKET_SIZE:
            raise ProtocolError(
                "Declared TCP packet size exceeds the "
                "maximum permitted size."
            )

        body = cls.receive_exactly(
            connection,
            packet_size,
        )

        return cls.decode_packet(body)

    @staticmethod
    def receive_exactly(
        connection: socket.socket,
        number_of_bytes: int,
    ) -> bytes:
        """
        Receive exactly the requested number of TCP bytes.

        Multiple calls to recv() may be required because TCP may divide
        the byte stream into arbitrary segments.
        """

        if not isinstance(number_of_bytes, int):
            raise TypeError(
                "Requested byte count must be an integer."
            )

        if number_of_bytes <= 0:
            raise ValueError(
                "Requested byte count must be greater than zero."
            )

        received = bytearray()

        while len(received) < number_of_bytes:
            remaining = number_of_bytes - len(received)

            try:
                chunk = connection.recv(remaining)

            except OSError as error:
                raise ConnectionError(
                    f"Failed while receiving TCP data: {error}"
                ) from error

            if not chunk:
                raise ConnectionClosedError(
                    "The remote peer closed the TCP connection "
                    "before the complete packet was received."
                )

            received.extend(chunk)

        return bytes(received)

    @classmethod
    def validate_packet(
        cls,
        packet: dict[str, Any],
    ) -> None:
        """
        Verify that a packet follows the expected protocol structure.
        """

        if not isinstance(packet, dict):
            raise ProtocolError(
                "Packet must be a dictionary."
            )

        required_fields = {
            "version",
            "packet_id",
            "type",
            "sender",
            "timestamp",
            "payload",
        }

        actual_fields = set(packet.keys())

        missing_fields = required_fields - actual_fields

        if missing_fields:
            missing_text = ", ".join(
                sorted(missing_fields)
            )

            raise ProtocolError(
                f"Packet is missing required fields: {missing_text}."
            )

        if packet["version"] != cls.PROTOCOL_VERSION:
            raise ProtocolError(
                "Unsupported network-protocol version."
            )

        cls._normalize_message_type(packet["type"])

        try:
            uuid.UUID(str(packet["packet_id"]))

        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError(
                "Packet identifier is not a valid UUID."
            ) from error

        sender = packet["sender"]

        if sender is not None:
            if not isinstance(sender, str):
                raise ProtocolError(
                    "Packet sender must be a string or None."
                )

            if not sender.strip():
                raise ProtocolError(
                    "Packet sender cannot be empty."
                )

            if len(sender) > 100:
                raise ProtocolError(
                    "Packet sender is too long."
                )

        timestamp = packet["timestamp"]

        if not isinstance(timestamp, str):
            raise ProtocolError(
                "Packet timestamp must be a string."
            )

        try:
            datetime.fromisoformat(timestamp)

        except ValueError as error:
            raise ProtocolError(
                "Packet timestamp is not valid ISO-8601."
            ) from error

        if not isinstance(packet["payload"], dict):
            raise ProtocolError(
                "Packet payload must be a dictionary."
            )

    @staticmethod
    def encode_bytes(value: bytes) -> str:
        """
        Convert binary cryptographic data into Base64 text.

        JSON cannot directly carry Python bytes. RSA ciphertext,
        AES ciphertext, nonces, tags and keys must therefore be
        Base64-encoded before transmission.
        """

        if not isinstance(value, bytes):
            raise TypeError(
                "Only bytes can be Base64-encoded."
            )

        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def decode_bytes(value: str) -> bytes:
        """
        Decode a validated Base64 string back into bytes.
        """

        if not isinstance(value, str):
            raise TypeError(
                "Base64 input must be supplied as a string."
            )

        try:
            return base64.b64decode(
                value.encode("ascii"),
                validate=True,
            )

        except (
            UnicodeEncodeError,
            binascii.Error,
            ValueError,
        ) as error:
            raise ProtocolError(
                "The supplied value is not valid Base64."
            ) from error

    @classmethod
    def get_message_type(
        cls,
        packet: dict[str, Any],
    ) -> MessageType:
        """
        Return a packet's type as a MessageType enumeration value.
        """

        cls.validate_packet(packet)

        return MessageType(packet["type"])

    @staticmethod
    def _validate_socket(
        connection: socket.socket,
    ) -> None:
        """Confirm that a valid socket object was supplied."""

        if not isinstance(connection, socket.socket):
            raise TypeError(
                "A valid socket.socket object is required."
            )

        if connection.fileno() < 0:
            raise ConnectionClosedError(
                "The TCP socket has already been closed."
            )

    @staticmethod
    def _normalize_message_type(
        message_type: MessageType | str,
    ) -> MessageType:
        """Convert a string or enumeration into MessageType."""

        if isinstance(message_type, MessageType):
            return message_type

        if isinstance(message_type, str):
            try:
                return MessageType(message_type)

            except ValueError as error:
                raise ProtocolError(
                    f"Unsupported packet type: {message_type!r}."
                ) from error

        raise ProtocolError(
            "Packet type must be a MessageType or string."
        )