# CryptoBase
Package | NuGet
-|-
CryptoBase | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase/)
CryptoBase.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.Abstractions.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.Abstractions/)

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
| Blake3 | ⏳ |
| MD5 | ✅ |
| SHA1 | ✅ |
| SHA224 | ✅ |
| SHA256 | ✅ |
| SHA384 | ✅ |
| SHA512 | ✅ |
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

### Key derivation functions

| Algorithms | Status |
| ---------- |:------:|
| HKDF | ✅ |
| Argon2id | ⚠️ |

### Symmetric-key algorithms

#### Stream ciphers

| Algorithms | Status |
| ---------- |:------:|
| ChaCha20 (IETF) | ✅ |
| ChaCha20 (Original) | ✅ |
| RC4 | ✅ |
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

#### Authenticated encryption algorithms

| Algorithms | Status |
| ---------- |:------:|
| AES-CCM | ⏳ |
| AES-GCM | ✅ |
| ChaCha20Poly1305 | ✅ |
| SM4-CCM | ⏳ |
| SM4-GCM | ✅ |
| XChaCha20Poly1305 | ✅ |

### Asymmetric cryptography

| Algorithms | Status |
| ---------- |:------:|
| ECDH | ⚠️ |
| ECDSA | ⚠️ |
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
| ML-KEM | ⚠️ |
| HQC | ⚠️ |

#### Hybrid key agreement mechanisms

| Algorithms | Status |
| ---------- |:------:|
| X25519MLKEM768 | ⚠️ |

#### Digital signature algorithms

| Algorithms | Status |
| ---------- |:------:|
| ML-DSA | ⚠️ |
| SLH-DSA | ⚠️ |
| FN-DSA | ⚠️ |
