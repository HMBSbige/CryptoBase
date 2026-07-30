# CryptoBase
Package | NuGet
-|-
CryptoBase | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase/)
CryptoBase.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.Abstractions.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.Abstractions/)
CryptoBase.BouncyCastle | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.BouncyCastle.svg?logo=nuget)](https://www.nuget.org/packages/CryptoBase.BouncyCastle/)

A fast crypto library for .NET

## Status

| Icon | Description |
|:----:|-------------|
| ⚠️ | Pending |
| ⏳ | Underway |
| ✅ | Done |

### Digest algorithms

| Algorithms | Status |
| ---------- |:------:|
| Blake3 | ⚠️ |
| CRC-32 | ✅ |
| CRC-32C | ✅ |
| MD5 | ✅ |
| SHA1 | ✅ |
| SHA224 | ⚠️ |
| SHA256 | ✅ |
| SHA384 | ✅ |
| SHA512 | ✅ |
| SM3 | ✅ |

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
| CFB128 | ✅ |
| CTR128 | ✅ |
| XTS | ✅ |

#### Authenticated encryption algorithms

| Algorithms | Status |
| ---------- |:------:|
| AES-GCM | ✅ |
| ChaCha20Poly1305 | ✅ |
| SM4-GCM | ✅ |
| XChaCha20Poly1305 | ✅ |

### Asymmetric cryptography

| Algorithms | Status |
| ---------- |:------:|
| RSA | ⏳ |
| Curve25519 | ⏳ |
| Ed25519 | ⏳ |
| SM2 | ⏳ |
| SM9 | ⏳ |

### Post-quantum cryptography

#### Key encapsulation mechanisms

| Algorithms | Status |
| ---------- |:------:|
| ML-KEM | ⚠️ |
| HQC | ⚠️ |

#### Digital signature algorithms

| Algorithms | Status |
| ---------- |:------:|
| ML-DSA | ⚠️ |
| SLH-DSA | ⚠️ |
| FN-DSA | ⚠️ |
