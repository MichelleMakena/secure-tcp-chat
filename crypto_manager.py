"""
Cryptographic services for the Secure TCP Chat Application.

Implemented functionality:

Stage 3:
1. RSA-2048 key-pair generation.
2. RSA mathematical parameter extraction.
3. Euler-totient and Carmichael-function verification.
4. Textbook RSA equation demonstration.
5. RSA public-key export and fingerprint generation.

Stage 4:
1. AES-256 key generation.
2. AES-GCM encryption.
3. AES-GCM decryption and authentication.
4. Text encryption and decryption helpers.

RSA-OAEP key protection will be added in Stage 5.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

@dataclass(frozen=True)
class RSAParameters:
    """Store the mathematical parameters of an RSA key pair."""

    p: int
    q: int
    n: int
    phi_n: int
    lambda_n: int
    e: int
    d: int
    d_phi: int


@dataclass(frozen=True)
class RSAVerificationResult:
    """Store the results of RSA verification tests."""

    primes_are_different: bool
    modulus_is_correct: bool
    totient_is_correct: bool
    carmichael_value_is_correct: bool
    public_exponent_is_valid: bool
    phi_private_exponent_is_valid: bool
    library_private_exponent_is_valid: bool
    modulus_is_2048_bits: bool

    @property
    def all_tests_passed(self) -> bool:
        """Return True only when every RSA test passes."""

        return all(
            (
                self.primes_are_different,
                self.modulus_is_correct,
                self.totient_is_correct,
                self.carmichael_value_is_correct,
                self.public_exponent_is_valid,
                self.phi_private_exponent_is_valid,
                self.library_private_exponent_is_valid,
                self.modulus_is_2048_bits,
            )
        )


@dataclass(frozen=True)
class AESGCMEncryptedData:
    """
    Store the output produced by AES-GCM encryption.

    Attributes:
        nonce: Unique value used for one encryption operation.
        ciphertext: Encrypted form of the plaintext.
        tag: Authentication tag used to detect alteration.
    """

    nonce: bytes
    ciphertext: bytes
    tag: bytes


class CryptoManager:
    """
    Manage RSA and AES operations for the chat application.

    Alice will generate and retain an RSA private key.

    Bob will later:
    1. Import Alice's RSA public key.
    2. Generate an AES-256 session key.
    3. Encrypt the AES key using RSA-OAEP.

    Both parties will use AES-GCM for chat messages and files.
    """

    DEFAULT_RSA_KEY_SIZE = 2048
    DEFAULT_PUBLIC_EXPONENT = 65537

    AES_KEY_SIZE_BYTES = 32
    AES_NONCE_SIZE_BYTES = 12
    AES_TAG_SIZE_BYTES = 16

    def __init__(self) -> None:
        """Create an empty cryptographic manager."""

        self._private_key: Optional[RSA.RsaKey] = None
        self._public_key: Optional[RSA.RsaKey] = None

    # ================================================================
    # RSA PROPERTIES AND OPERATIONS
    # ================================================================

    @property
    def has_private_key(self) -> bool:
        """Return True when an RSA private key is available."""

        return self._private_key is not None

    @property
    def has_public_key(self) -> bool:
        """Return True when an RSA public key is available."""

        return self._public_key is not None

    def generate_rsa_key_pair(
        self,
        key_size: int = DEFAULT_RSA_KEY_SIZE,
    ) -> tuple[RSA.RsaKey, RSA.RsaKey]:
        """
        Generate an RSA public/private key pair.

        Args:
            key_size: RSA modulus size in bits.

        Returns:
            A tuple containing the private key and public key.

        Raises:
            ValueError: If a key size below 2048 bits is requested.
        """

        if key_size < self.DEFAULT_RSA_KEY_SIZE:
            raise ValueError(
                "RSA key size must be at least 2048 bits."
            )

        self._private_key = RSA.generate(
            bits=key_size,
            randfunc=get_random_bytes,
            e=self.DEFAULT_PUBLIC_EXPONENT,
        )

        self._public_key = self._private_key.publickey()

        return self._private_key, self._public_key

    def get_rsa_parameters(self) -> RSAParameters:
        """Extract and calculate the RSA mathematical parameters."""

        private_key = self._require_private_key()

        p = int(private_key.p)
        q = int(private_key.q)
        n = int(private_key.n)
        e = int(private_key.e)
        d = int(private_key.d)

        phi_n = (p - 1) * (q - 1)
        lambda_n = math.lcm(p - 1, q - 1)
        d_phi = pow(e, -1, phi_n)

        return RSAParameters(
            p=p,
            q=q,
            n=n,
            phi_n=phi_n,
            lambda_n=lambda_n,
            e=e,
            d=d,
            d_phi=d_phi,
        )

    def verify_rsa_parameters(self) -> RSAVerificationResult:
        """Verify the mathematical relationships of the RSA key."""

        parameters = self.get_rsa_parameters()

        expected_n = parameters.p * parameters.q
        expected_phi_n = (
            parameters.p - 1
        ) * (
            parameters.q - 1
        )

        expected_lambda_n = math.lcm(
            parameters.p - 1,
            parameters.q - 1,
        )

        return RSAVerificationResult(
            primes_are_different=(
                parameters.p != parameters.q
            ),

            modulus_is_correct=(
                parameters.n == expected_n
            ),

            totient_is_correct=(
                parameters.phi_n == expected_phi_n
            ),

            carmichael_value_is_correct=(
                parameters.lambda_n == expected_lambda_n
            ),

            public_exponent_is_valid=(
                1 < parameters.e < parameters.phi_n
                and math.gcd(
                    parameters.e,
                    parameters.phi_n,
                )
                == 1
            ),

            phi_private_exponent_is_valid=(
                parameters.e * parameters.d_phi
            )
            % parameters.phi_n
            == 1,

            library_private_exponent_is_valid=(
                parameters.e * parameters.d
            )
            % parameters.lambda_n
            == 1,

            modulus_is_2048_bits=(
                parameters.n.bit_length()
                == self.DEFAULT_RSA_KEY_SIZE
            ),
        )

    def textbook_rsa_encrypt(self, message: int) -> int:
        """
        Demonstrate textbook RSA encryption.

        Equation:
            C = M^e mod n

        Textbook RSA is for academic demonstration only.
        """

        public_key = self._require_public_key()

        if not 0 <= message < public_key.n:
            raise ValueError(
                "Message must satisfy 0 <= M < n."
            )

        return pow(
            message,
            int(public_key.e),
            int(public_key.n),
        )

    def textbook_rsa_decrypt(self, ciphertext: int) -> int:
        """
        Demonstrate textbook RSA decryption.

        Equation:
            M = C^d mod n
        """

        private_key = self._require_private_key()

        if not 0 <= ciphertext < private_key.n:
            raise ValueError(
                "Ciphertext must satisfy 0 <= C < n."
            )

        return pow(
            ciphertext,
            int(private_key.d),
            int(private_key.n),
        )

    def textbook_rsa_decrypt_using_phi(
        self,
        ciphertext: int,
    ) -> int:
        """
        Decrypt using the traditional private exponent d_phi.

        Equation:
            d_phi = e^(-1) mod phi(n)
        """

        parameters = self.get_rsa_parameters()

        if not 0 <= ciphertext < parameters.n:
            raise ValueError(
                "Ciphertext must satisfy 0 <= C < n."
            )

        return pow(
            ciphertext,
            parameters.d_phi,
            parameters.n,
        )

    def export_public_key(self) -> bytes:
        """Export Alice's RSA public key in PEM format."""

        public_key = self._require_public_key()
        return public_key.export_key(format="PEM")

    def export_private_key(
        self,
        passphrase: Optional[str] = None,
    ) -> bytes:
        """
        Export Alice's RSA private key.

        The private key must never be transmitted to Bob.
        """

        private_key = self._require_private_key()

        if passphrase:
            return private_key.export_key(
                format="PEM",
                passphrase=passphrase,
                pkcs=8,
                protection="scryptAndAES128-CBC",
            )

        return private_key.export_key(
            format="PEM",
            pkcs=8,
        )

    def get_public_key_fingerprint(self) -> str:
        """Calculate a SHA-256 fingerprint of the public key."""

        public_key = self._require_public_key()
        public_der = public_key.export_key(format="DER")

        digest = sha256(public_der).hexdigest().upper()

        return ":".join(
            digest[index:index + 2]
            for index in range(0, len(digest), 2)
        )

    def get_key_size(self) -> int:
        """Return the RSA modulus size in bits."""

        public_key = self._require_public_key()
        return int(public_key.n).bit_length()
        # ================================================================
    # RSA-OAEP HYBRID KEY-EXCHANGE OPERATIONS
    # ================================================================

    def import_public_key(
        self,
        public_key_data: bytes,
    ) -> RSA.RsaKey:
        """
        Import Alice's RSA public key.

        Bob will call this method after receiving Alice's public key
        through the TCP connection.

        Args:
            public_key_data: RSA public key encoded in PEM or DER form.

        Returns:
            Imported RSA public-key object.

        Raises:
            TypeError: If public_key_data is not bytes.
            ValueError: If the key is invalid or smaller than 2048 bits.
        """

        if not isinstance(public_key_data, bytes):
            raise TypeError(
                "The RSA public key must be supplied as bytes."
            )

        try:
            imported_key = RSA.import_key(public_key_data)

        except (ValueError, IndexError, TypeError) as error:
            raise ValueError(
                "The supplied RSA public key is invalid."
            ) from error

        # Even if private-key material is accidentally supplied,
        # retain only the public portion on Bob's side.
        public_key = imported_key.publickey()

        if public_key.size_in_bits() < self.DEFAULT_RSA_KEY_SIZE:
            raise ValueError(
                "The RSA public key must be at least 2048 bits."
            )

        self._public_key = public_key

        return public_key

    def import_private_key(
        self,
        private_key_data: bytes,
        passphrase: Optional[str] = None,
    ) -> RSA.RsaKey:
        """
        Import an RSA private key.

        This method is included for controlled recovery of Alice's
        private key. It must never be used to transmit a private key.

        Args:
            private_key_data: Private key encoded as PEM or DER bytes.
            passphrase: Optional passphrase for an encrypted key.

        Returns:
            Imported RSA private-key object.

        Raises:
            TypeError: If the supplied key is not bytes.
            ValueError: If the data does not contain a valid private key.
        """

        if not isinstance(private_key_data, bytes):
            raise TypeError(
                "The RSA private key must be supplied as bytes."
            )

        try:
            imported_key = RSA.import_key(
                private_key_data,
                passphrase=passphrase,
            )

        except (ValueError, IndexError, TypeError) as error:
            raise ValueError(
                "The supplied RSA private key is invalid."
            ) from error

        if not imported_key.has_private():
            raise ValueError(
                "The supplied RSA key does not contain a private key."
            )

        if imported_key.size_in_bits() < self.DEFAULT_RSA_KEY_SIZE:
            raise ValueError(
                "The RSA private key must be at least 2048 bits."
            )

        self._private_key = imported_key
        self._public_key = imported_key.publickey()

        return imported_key

    def get_rsa_oaep_max_message_size(self) -> int:
        """
        Calculate the maximum OAEP plaintext size for RSA and SHA-256.

        Formula:
            maximum = k - 2(hLen) - 2

        where:
            k = RSA modulus size in bytes
            hLen = SHA-256 digest size in bytes

        For RSA-2048 with SHA-256:
            256 - 2(32) - 2 = 190 bytes
        """

        public_key = self._require_public_key()

        modulus_size_bytes = public_key.size_in_bytes()
        hash_size_bytes = SHA256.new().digest_size

        return (
            modulus_size_bytes
            - (2 * hash_size_bytes)
            - 2
        )

    def encrypt_aes_key(
        self,
        aes_key: bytes,
    ) -> bytes:
        """
        Encrypt an AES-256 session key using RSA-OAEP and SHA-256.

        Bob calls this method using Alice's imported RSA public key.

        Args:
            aes_key: Bob's 32-byte AES-256 session key.

        Returns:
            RSA-OAEP ciphertext.

        Raises:
            RuntimeError: If no RSA public key is available.
            ValueError: If the AES key is not exactly 32 bytes.
        """

        self._validate_aes_key(aes_key)

        public_key = self._require_public_key()

        oaep_cipher = PKCS1_OAEP.new(
            public_key,
            hashAlgo=SHA256,
        )

        try:
            return oaep_cipher.encrypt(aes_key)

        except ValueError as error:
            raise ValueError(
                "RSA-OAEP encryption failed. The plaintext may "
                "be too large for the RSA key."
            ) from error

    def decrypt_aes_key(
        self,
        encrypted_aes_key: bytes,
    ) -> bytes:
        """
        Decrypt an RSA-OAEP-protected AES session key.

        Alice calls this method using her RSA private key.

        Args:
            encrypted_aes_key: RSA-OAEP ciphertext received from Bob.

        Returns:
            Recovered 32-byte AES-256 key.

        Raises:
            RuntimeError: If Alice's private key is unavailable.
            TypeError: If the ciphertext is not bytes.
            ValueError: If OAEP verification fails.
        """

        if not isinstance(encrypted_aes_key, bytes):
            raise TypeError(
                "The encrypted AES key must be supplied as bytes."
            )

        private_key = self._require_private_key()

        expected_ciphertext_size = private_key.size_in_bytes()

        if len(encrypted_aes_key) != expected_ciphertext_size:
            raise ValueError(
                "The RSA-OAEP ciphertext has an invalid length."
            )

        oaep_cipher = PKCS1_OAEP.new(
            private_key,
            hashAlgo=SHA256,
        )

        try:
            recovered_aes_key = oaep_cipher.decrypt(
                encrypted_aes_key
            )

        except ValueError as error:
            raise ValueError(
                "RSA-OAEP decryption failed. The ciphertext may "
                "be altered or encrypted using another public key."
            ) from error

        self._validate_aes_key(recovered_aes_key)

        return recovered_aes_key

    # ================================================================
    # AES-256-GCM OPERATIONS
    # ================================================================

    def generate_aes_key(self) -> bytes:
        """
        Generate a cryptographically secure AES-256 key.

        Returns:
            A random 32-byte key.

        Security:
            The returned key must not be printed, logged or transmitted
            without RSA protection.
        """

        return get_random_bytes(
            self.AES_KEY_SIZE_BYTES
        )

    def encrypt_data(
        self,
        plaintext: bytes,
        aes_key: bytes,
        associated_data: bytes = b"",
    ) -> AESGCMEncryptedData:
        """
        Encrypt bytes using AES-256-GCM.

        Args:
            plaintext: Data that must be encrypted.
            aes_key: Exactly 32 bytes.
            associated_data: Optional metadata that is authenticated
                but not encrypted.

        Returns:
            AESGCMEncryptedData containing nonce, ciphertext and tag.

        Raises:
            TypeError: If plaintext or associated data is not bytes.
            ValueError: If the key is not exactly 32 bytes.
        """

        self._validate_aes_key(aes_key)

        if not isinstance(plaintext, bytes):
            raise TypeError(
                "AES plaintext must be supplied as bytes."
            )

        if not isinstance(associated_data, bytes):
            raise TypeError(
                "Associated data must be supplied as bytes."
            )

        # A fresh 96-bit nonce is generated for every encryption.
        nonce = get_random_bytes(
            self.AES_NONCE_SIZE_BYTES
        )

        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=nonce,
            mac_len=self.AES_TAG_SIZE_BYTES,
        )

        if associated_data:
            cipher.update(associated_data)

        ciphertext, tag = cipher.encrypt_and_digest(
            plaintext
        )

        return AESGCMEncryptedData(
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt_data(
        self,
        encrypted_data: AESGCMEncryptedData,
        aes_key: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """
        Decrypt and authenticate AES-256-GCM data.

        The plaintext is returned only when the authentication tag is
        valid.

        Args:
            encrypted_data: Nonce, ciphertext and tag.
            aes_key: Same 32-byte key used for encryption.
            associated_data: Same authenticated metadata supplied
                during encryption.

        Returns:
            Authenticated plaintext bytes.

        Raises:
            TypeError: If an invalid data type is provided.
            ValueError: If authentication fails or sizes are invalid.
        """

        self._validate_aes_key(aes_key)

        if not isinstance(
            encrypted_data,
            AESGCMEncryptedData,
        ):
            raise TypeError(
                "encrypted_data must be AESGCMEncryptedData."
            )

        if not isinstance(associated_data, bytes):
            raise TypeError(
                "Associated data must be supplied as bytes."
            )

        if (
            len(encrypted_data.nonce)
            != self.AES_NONCE_SIZE_BYTES
        ):
            raise ValueError(
                "AES-GCM nonce must be exactly 12 bytes."
            )

        if (
            len(encrypted_data.tag)
            != self.AES_TAG_SIZE_BYTES
        ):
            raise ValueError(
                "AES-GCM authentication tag must be 16 bytes."
            )

        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=encrypted_data.nonce,
            mac_len=self.AES_TAG_SIZE_BYTES,
        )

        if associated_data:
            cipher.update(associated_data)

        try:
            return cipher.decrypt_and_verify(
                encrypted_data.ciphertext,
                encrypted_data.tag,
            )

        except ValueError as error:
            raise ValueError(
                "AES-GCM authentication failed. The key, nonce, "
                "ciphertext, tag or associated data is incorrect "
                "or has been modified."
            ) from error

    def encrypt_text(
        self,
        plaintext: str,
        aes_key: bytes,
        associated_data: bytes = b"",
    ) -> AESGCMEncryptedData:
        """
        Convert text to UTF-8 and encrypt it with AES-256-GCM.
        """

        if not isinstance(plaintext, str):
            raise TypeError(
                "Plaintext must be a string."
            )

        return self.encrypt_data(
            plaintext=plaintext.encode("utf-8"),
            aes_key=aes_key,
            associated_data=associated_data,
        )

    def decrypt_text(
        self,
        encrypted_data: AESGCMEncryptedData,
        aes_key: bytes,
        associated_data: bytes = b"",
    ) -> str:
        """
        Decrypt AES-GCM data and decode it as UTF-8 text.
        """

        plaintext_bytes = self.decrypt_data(
            encrypted_data=encrypted_data,
            aes_key=aes_key,
            associated_data=associated_data,
        )

        try:
            return plaintext_bytes.decode("utf-8")

        except UnicodeDecodeError as error:
            raise ValueError(
                "The authenticated plaintext is not valid UTF-8 text."
            ) from error

    def calculate_sha256(self, data: bytes) -> str:
        """
        Calculate a hexadecimal SHA-256 digest.

        This will later be used to verify transferred files.
        """

        if not isinstance(data, bytes):
            raise TypeError(
                "SHA-256 input must be bytes."
            )

        return sha256(data).hexdigest()

    # ================================================================
    # INTERNAL VALIDATION METHODS
    # ================================================================

    def _validate_aes_key(self, aes_key: bytes) -> None:
        """Confirm that an AES-256 key is exactly 32 bytes."""

        if not isinstance(aes_key, bytes):
            raise TypeError(
                "AES key must be supplied as bytes."
            )

        if len(aes_key) != self.AES_KEY_SIZE_BYTES:
            raise ValueError(
                "AES-256 requires a key of exactly 32 bytes."
            )

    def _require_private_key(self) -> RSA.RsaKey:
        """Return the private key or raise an error."""

        if self._private_key is None:
            raise RuntimeError(
                "Generate the RSA key pair first."
            )

        return self._private_key

    def _require_public_key(self) -> RSA.RsaKey:
        """Return the public key or raise an error."""

        if self._public_key is None:
            raise RuntimeError(
                "Generate or import the RSA public key first."
            )

        return self._public_key