# CryptoBase
Channel | Status
-|-
CI | [![CI](https://github.com/HMBSbige/CryptoBase/workflows/CI/badge.svg)](https://github.com/HMBSbige/CryptoBase/actions)
CryptoBase | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.svg)](https://www.nuget.org/packages/CryptoBase/)
CryptoBase.Abstractions | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.Abstractions.svg)](https://www.nuget.org/packages/CryptoBase.Abstractions/)
CryptoBase.BouncyCastle | [![NuGet.org](https://img.shields.io/nuget/v/CryptoBase.BouncyCastle.svg)](https://www.nuget.org/packages/CryptoBase.BouncyCastle/)

A fast crypto library for .NET

[Wiki & Benchmark](https://github.com/HMBSbige/CryptoBase/wiki)

## Status

Icon | Description
-- | --
⚠️ | Pending
⏳ | Underway
✅ | Done
💔 | Never implemented

### Hardware Acceleration
* ✅ x86
* ⚠️ Arm

### Digest algorithms
* ✅ MD5
* ⏳ SHA1
* ⏳ SHA256
* ⏳ SHA512
* ✅ SM3

### Symmetric-key algorithms
#### Stream ciphers
* ✅ ChaCha20
    * ✅ Original
    * ✅ IETF 7539
* ✅ RC4
* ✅ Salsa20
* ✅ XChaCha20
* ✅ XSalsa20

#### Block ciphers
* ✅ AES
* ✅ SM4

##### Block cipher modes
* ✅ CBC
* ✅ CFB128 Stream
* ✅ CTR128 Stream

#### Authenticated encryption algorithms
* ✅ AES-GCM
* ✅ ChaCha20Poly1305
* ✅ SM4-GCM
* ✅ XChaCha20Poly1305

### Asymmetric cryptography
* ⚠️ Curve25519
* ⚠️ Ed25519
* 💔 RSA
* ⚠️ SM2
* ⚠️ SM9
