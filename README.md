# CryptoBase
Package | NuGet
-|-
CryptoBase | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase/)
CryptoBase.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.Abstractions.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.Abstractions/)
CryptoBase.IO | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.IO.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.IO/)

A fast crypto library for .NET

See the [documentation](docs/README.md) for installation and usage guides.

## Status

| Icon | Description |
|:----:|-------------|
| ⚠️ | Pending |
| ⏳ | Underway |
| ✅ | Done |

### Data formats

| Formats | Status |
| ------- |:------:|
| Base32 | ✅ |

### Hash algorithms and checksums

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

### Message authentication codes

| Algorithms | Status |
| ---------- |:------:|
| HMAC | ✅ |
| Poly1305 | ✅ |
| KMAC128 | ✅ |
| KMAC256 | ✅ |
| KMACXOF128 | ✅ |
| KMACXOF256 | ✅ |

### Key derivation functions

| Algorithms | Status |
| ---------- |:------:|
| Argon2d | ✅ |
| Argon2i | ✅ |
| Argon2id | ✅ |
| HKDF | ✅ |
| TLS 1.2 PRF | ✅ |

### Symmetric-key algorithms

#### Stream ciphers

| Algorithms | Status |
| ---------- |:------:|
| ChaCha20 (IETF) | ✅ |
| ChaCha20 (Original) | ✅ |
| Salsa20 | ✅ |
| XChaCha20 | ✅ |
| XSalsa20 | ✅ |

#### Block ciphers

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
| None | ✅ |
| Zeros | ✅ |
| PKCS #7 | ✅ |
| ANSI X9.23 | ✅ |
| ISO 10126 | ✅ |

#### Authenticated encryption algorithms

| Algorithms | Status |
| ---------- |:------:|
| AES-CCM | ✅ |
| AES-GCM | ✅ |
| ChaCha20-Poly1305 | ✅ |
| SM4-CCM | ✅ |
| SM4-GCM | ✅ |
| XChaCha20-Poly1305 | ✅ |

### Asymmetric cryptography

| Algorithms | Status |
| ---------- |:------:|
| ECDH | ✅ |
| ECDSA | ✅ |
| RSA | ⚠️ |
| X25519 | ⚠️ |
| X448 | ⚠️ |
| Ed25519 | ⚠️ |
| Ed448 | ⚠️ |
| SM2 | ⚠️ |
| SM9 | ⚠️ |

### Post-quantum cryptography

#### Key encapsulation mechanisms

| Algorithms | Status |
| ---------- |:------:|
| ML-KEM | ✅ |
| HQC | ⚠️ |

#### Hybrid key agreement mechanisms

| Algorithms | Status |
| ---------- |:------:|
| X25519MLKEM768 | ⚠️ |

#### Digital signature algorithms

| Algorithms | Status |
| ---------- |:------:|
| ML-DSA | ✅ |
| SLH-DSA | ⚠️ |
| FN-DSA | ⚠️ |
