# CryptoBase
Package | NuGet
-|-
CryptoBase | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase/)
CryptoBase.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.Abstractions.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.Abstractions/)
CryptoBase.IO | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.IO.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.IO/)
CryptoBase.X509 | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.X509.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.X509/)

A fast crypto library for .NET

See the [documentation](docs/README.md) for installation and usage guides.

## Status

| Icon | Description |
|:----:|-------------|
| ⚠️ | Pending |
| ⏳ | Underway |
| ✅ | Done |

### [Data formats](docs/data-formats.md)

| Formats | Status |
| ------- |:------:|
| Base32 | ✅ |

### [Hash algorithms and checksums](docs/hashes.md)

#### Cryptographic hash algorithms

| Algorithms | Status |
| ---------- |:------:|
| BLAKE2b | ✅ |
| BLAKE3 | ✅ |
| MD5 | ✅ |
| SHA-1 | ✅ |
| SHA-224 | ✅ |
| SHA-256 | ✅ |
| SHA-384 | ✅ |
| SHA-512 | ✅ |
| SHA3-224 | ✅ |
| SHA3-256 | ✅ |
| SHA3-384 | ✅ |
| SHA3-512 | ✅ |
| SHAKE128 | ✅ |
| SHAKE256 | ✅ |
| cSHAKE128 | ✅ |
| cSHAKE256 | ✅ |
| SM3 | ✅ |

#### Non-cryptographic checksums

| Algorithms | Status |
| ---------- |:------:|
| CRC-32 | ✅ |
| CRC-32C | ✅ |

### [Message authentication codes](docs/macs-and-key-derivation.md)

| Algorithms | Status |
| ---------- |:------:|
| HMAC | ✅ |
| Poly1305 | ✅ |
| KMAC128 | ✅ |
| KMAC256 | ✅ |
| KMACXOF128 | ✅ |
| KMACXOF256 | ✅ |

### [Key derivation functions](docs/macs-and-key-derivation.md)

| Algorithms | Status |
| ---------- |:------:|
| Argon2d | ✅ |
| Argon2i | ✅ |
| Argon2id | ✅ |
| HKDF | ✅ |
| TLS 1.2 PRF | ✅ |

### [One-time passwords](docs/one-time-passwords.md)

| Algorithms | Status |
| ---------- |:------:|
| HOTP | ✅ |
| TOTP | ✅ |
| Steam Guard | ✅ |

### Symmetric-key algorithms

#### [Stream ciphers](docs/stream-ciphers.md)

| Algorithms | Status |
| ---------- |:------:|
| ChaCha20 (IETF) | ✅ |
| ChaCha20 (Original) | ✅ |
| Salsa20 | ✅ |
| XChaCha20 | ✅ |
| XSalsa20 | ✅ |

#### [Block ciphers](docs/block-ciphers-and-modes.md)

| Algorithms | Status |
| ---------- |:------:|
| AES | ✅ |
| SM4 | ✅ |

##### Block cipher modes

| Algorithms | Status |
| ---------- |:------:|
| CTR128 | ✅ |
| XTS | ✅ |

##### Padding

| Modes | Status |
| ----- |:------:|
| Zeros | ✅ |
| PKCS #7 | ✅ |
| ANSI X9.23 | ✅ |
| ISO 10126 | ✅ |

#### [Authenticated encryption algorithms](docs/authenticated-encryption.md)

| Algorithms | Status |
| ---------- |:------:|
| AES-CCM | ✅ |
| AES-GCM | ✅ |
| ChaCha20-Poly1305 | ✅ |
| Cobblestone-128 | ✅ |
| Cobblestone-256 | ✅ |
| SM4-CCM | ✅ |
| SM4-GCM | ✅ |
| XChaCha20-Poly1305 | ✅ |

### Asymmetric cryptography

| Algorithms | Status |
| ---------- |:------:|
| [ECDH](docs/key-agreement.md) | ✅ |
| [ECDSA](docs/digital-signatures.md) | ✅ |
| [RSA](docs/digital-signatures.md) | ✅ |
| [X25519](docs/key-agreement.md) | ✅ |
| [X448](docs/key-agreement.md) | ✅ |
| [Ed25519](docs/digital-signatures.md) | ✅ |
| Ed448 | ⏳ |
| SM2 | ⏳ |
| SM9 | ⏳ |

### [Hybrid public key encryption](docs/hpke.md)

| Features | Status |
| -------- |:------:|
| Base, PSK, auth and auth_psk modes | ✅ |
| HKDF-SHA256, HKDF-SHA384, HKDF-SHA512 | ✅ |
| AES-128-GCM, AES-256-GCM, ChaCha20Poly1305, export-only | ✅ |
| DHKEM(P-256, HKDF-SHA256) | ✅ |
| DHKEM(P-384, HKDF-SHA384) | ✅ |
| DHKEM(P-521, HKDF-SHA512) | ✅ |
| DHKEM(X25519, HKDF-SHA256) | ✅ |
| DHKEM(X448, HKDF-SHA512) | ⚠️ |

### Post-quantum cryptography

#### [Key encapsulation mechanisms](docs/key-encapsulation.md)

| Algorithms | Status |
| ---------- |:------:|
| ML-KEM | ✅ |
| HQC | ⚠️ |

#### [Hybrid key agreement mechanisms](docs/key-encapsulation.md#hybrid-kems)

| Algorithms | Status |
| ---------- |:------:|
| SecP256r1MLKEM768 | ✅ |
| SecP384r1MLKEM1024 | ✅ |
| X25519MLKEM768 | ✅ |

#### [Digital signature algorithms](docs/digital-signatures.md)

| Algorithms | Status |
| ---------- |:------:|
| ML-DSA | ✅ |
| SLH-DSA | ⚠️ |
| FN-DSA | ⚠️ |

### [X.509](docs/x509.md)

| Features | Status |
| -------- |:------:|
| Certificate decoding | ✅ |
| Self-signed certificates | ✅ |
| Host name matching (RFC 9525) | ✅ |
| Chain validation through the platform | ✅ |
| Path validation (RFC 5280) | ✅ |
| Certificate fingerprints (RFC 8122) | ✅ |
| Certificate signing requests | ⏳ |
| CRL | ⏳ |
| OCSP | ⚠️ |

### [Stream and file I/O](docs/io.md)

| Features | Status |
| -------- |:------:|
| Stream hashing | ✅ |
| Stream MACs | ✅ |
| XTS random access and streams | ✅ |
| Cobblestone encryption and decryption streams | ✅ |
| Cobblestone random access | ✅ |
