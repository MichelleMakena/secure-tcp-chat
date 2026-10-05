# Secure TCP Chat

A secure client-server chat and file-transfer application built in Python to demonstrate practical **hybrid cryptography**, authenticated encryption, secure key exchange, network protocol design, and defensive software engineering.

The application uses **RSA-2048 with OAEP/SHA-256** to protect a randomly generated **AES-256 session key**, then uses **AES-256-GCM** for authenticated encryption of chat messages and file chunks. It also implements TCP message framing, SHA-256 file verification, multithreaded GUI operation, structured packet validation, secure logging, and negative security testing.



## Security Architecture

1. **Alice (server)** generates an RSA-2048 public/private key pair.
2. Alice sends only the RSA public key to **Bob (client)**.
3. Bob generates a cryptographically random 32-byte AES-256 session key.
4. Bob encrypts the AES key using **RSA-OAEP with SHA-256** and sends the ciphertext to Alice.
5. Alice recovers the AES key with her RSA private key.
6. Both peers use **AES-256-GCM** with a fresh nonce for every chat message and file chunk.
7. Files are accepted only after authenticated chunk processing, byte-count validation, and whole-file **SHA-256** verification.

```text
Alice / Server                              Bob / Client
--------------                              ------------
Generate RSA-2048 key pair
        |
        |---- RSA public key --------------------->|
        |                                          | Generate AES-256 session key
        |<--- RSA-OAEP(AES session key) -----------|
Decrypt session key                               |
        |                                          |
        |<==== AES-256-GCM secure session ========>|
        |      encrypted chat + file transfer      |
```

!\[Secure communication sequence](docs/communication-sequence.png)

## Application Demo

The GUI reports TCP connectivity and cryptographic session state while network and file operations run in background threads.

!\[Bob secure session GUI](docs/screenshots/secure-session-gui.png)

Authenticated chat and encrypted file transfer operate over the established AES-256-GCM session.

!\[Encrypted chat and file transfer](docs/screenshots/encrypted-chat-file-transfer.png)

### Security Failure Testing

The implementation was also tested against modified ciphertext/tags, incorrect keys, altered metadata and file-transfer failures. Invalid authenticated data is rejected rather than processed as trusted plaintext.

!\[Tamper detection tests](docs/screenshots/tamper-detection-tests.png)

Successful file reconstruction is published only after authentication and final SHA-256 verification.

!\[Verified encrypted file receipt](docs/screenshots/verified-file-receipt.png)

## Key Security Features

* RSA-2048 asymmetric cryptography for session-key protection
* RSA-OAEP with SHA-256 rather than raw/textbook RSA for operational key exchange
* AES-256-GCM authenticated encryption for confidentiality and integrity
* Fresh 12-byte GCM nonce for every encryption operation
* 16-byte GCM authentication tags
* Associated authenticated data binding messages/chunks to session metadata
* SHA-256 whole-file verification after encrypted transfer
* Four-byte length-prefixed JSON framing over TCP
* Validation of packet types, sizes, UUIDs, Base64 fields, key lengths, and filenames
* Filename sanitisation to reduce path-traversal risk
* Background networking/file threads to keep Tkinter responsive
* Queue-based GUI updates
* Rotating persistent logs with sensitive-data redaction
* Controlled disconnect and error handling

## Project Structure

```text
secure-tcp-chat/
├── alice\_gui.py             # Alice GUI launcher
├── bob\_gui.py               # Bob GUI launcher
├── alice\_server.py          # Command-line Alice server
├── bob\_client.py            # Command-line Bob client
├── crypto\_manager.py        # RSA, OAEP, AES-GCM and fingerprints
├── network\_protocol.py      # JSON packets, framing and validation
├── file\_transfer.py         # Encrypted file transfer and SHA-256 verification
├── gui\_backend.py           # Threaded networking backends
├── gui\_common.py            # Shared Tkinter interface components
├── logger\_config.py         # Rotating/redacted security logging
├── tests/                   # Cryptography, protocol, file and logging demonstrations
├── docs/screenshots/        # Portfolio screenshots can be added here
├── requirements.txt
└── .gitignore
```

## Running the Application

### 1\. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\\Scripts\\activate
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

### 2\. Install dependencies

```bash
pip install -r requirements.txt
```

### 3\. Start Alice

Open the first terminal:

```bash
python alice\_gui.py
```

Start the Alice server from the GUI.

### 4\. Start Bob

Open a second terminal:

```bash
python bob\_gui.py
```

Connect Bob to Alice. The default development configuration uses localhost.

## Security Testing

The project was tested using both valid and deliberately invalid inputs. Security-focused tests include:

|Test|Expected behaviour|
|-|-|
|Altered AES-GCM ciphertext|Authentication failure|
|Altered GCM tag|Authentication failure|
|Incorrect AES key|Authentication failure|
|Altered associated data|Authentication failure|
|Altered RSA-OAEP ciphertext|Key recovery rejected|
|Wrong RSA private key|Session key cannot be recovered|
|Fragmented/combined TCP data|Packets reconstructed correctly|
|Malformed JSON/Base64|Rejected safely|
|Oversized packet declaration|Rejected before unsafe processing|
|Incomplete packet|Controlled connection error|
|Out-of-order file chunk|Rejected before write|
|Unsafe filename|Path components sanitised|
|Sensitive value in log event|Secret material redacted|
|Unexpected disconnect|Controlled cleanup/state recovery|

The staged and integration tests used during development returned PASS for the expected valid and failure cases.

Example test commands:

```bash
python tests/stage3\_rsa\_demo.py
python tests/stage4\_aes\_demo.py
python tests/stage5\_hybrid\_key\_exchange.py
python tests/stage6\_network\_protocol\_demo.py
python tests/stage11\_file\_transfer\_demo.py
python tests/stage13\_logging\_tests.py
```

## What This Project Demonstrates

This project goes beyond simply encrypting a socket connection. It demonstrates several secure-design principles:

* choosing asymmetric and symmetric cryptography for appropriate roles;
* using authenticated encryption rather than confidentiality alone;
* treating TCP as a byte stream and explicitly defining application-message boundaries;
* authenticating file chunks before writing them;
* verifying the complete reconstructed file independently;
* validating untrusted network input;
* separating GUI operations from blocking network/file work; and
* testing failure and tampering cases rather than only successful operation.

## Limitations

This is an educational security prototype rather than a production messenger. Current limitations include:

* one Alice-Bob session at a time;
* no certificate authority or independently trusted peer identity;
* no forward secrecy because session-key protection uses long-term RSA;
* localhost-focused development and testing;
* no user-account or fine-grained authorisation system;
* no independent production security audit; and
* no guarantee of physical memory erasure for Python byte objects.

## Future Improvements

* X.509 certificates or another trusted public-key authentication mechanism
* Ephemeral Diffie-Hellman/ECDH for forward secrecy
* Explicit replay-protection windows
* Multi-client support with per-session keys
* File-size and bandwidth limits
* Static analysis, dependency scanning, fuzzing and penetration testing
* Reproducible packaging with pinned dependencies
* Investigation of post-quantum key encapsulation

## Technologies

`Python` `PyCryptodome` `RSA-2048` `RSA-OAEP` `AES-256-GCM` `SHA-256` `TCP/IP` `Sockets` `Tkinter` `Threading` `JSON`

## Author

**Michelle Makena**  
Cloud \& Cybersecurity | Information Security | AWS

