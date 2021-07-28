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

| Icon | Description |
|:----:|-----------|
⚠️ | Pending
⏳ | Underway
✅ | Done
💔 | Never implemented or help welcomed

### Digest algorithms

| Digests | Software Fallback | X86 | Arm |
| ------- |:-----------------:|:---:|:---:|
CRC-32 | ✅ | ✅ | ⏳
CRC-32C | ✅ | ✅ | ⏳
MD5 | ✅ | 💔 | 💔
SHA1 | ✅ | ⏳ | ⏳
SHA256 | ✅ | ⏳ | ⏳
SHA384 | ✅ | 💔 | ⏳
SHA512 | ✅ | ⏳ | ⏳
SM3 | ✅ | 💔 | ⏳

### Symmetric-key algorithms
#### Stream ciphers

| Ciphers | Software Fallback | X86 | Arm |
| ------- |:-----------------:|:---:|:---:|
ChaCha20(IETF 7539) | ✅ | ✅ | ⏳
ChaCha20(Original) | ✅ | ✅ | ⏳
RC4 | ✅ | 💔 | 💔
Salsa20 | ✅ | ✅ | ⏳
XChaCha20 | ✅ | ✅ | ⏳
XSalsa20 | ✅ | ✅ | ⏳

#### Block ciphers

| Ciphers | Software Fallback | X86 | Arm |
| ------- |:-----------------:|:---:|:---:|
AES | ✅ | ✅ | ⏳
SM4 | ✅ | ✅ | ⏳

##### Block cipher modes

* ✅ CBC
* ✅ CFB128(Stream)
* ✅ CTR128(Stream)

#### Authenticated encryption algorithms

| Ciphers | Software Fallback | X86 | Arm |
| ------- |:-----------------:|:---:|:---:|
AES-GCM | ✅ | ✅ | ⏳
ChaCha20Poly1305 | ✅ | ✅ | ⏳
SM4-GCM | ✅ | ✅ | ⏳
XChaCha20Poly1305 | ✅ | ✅ | ⏳

### Asymmetric cryptography

| Ciphers | Software Fallback | X86 | Arm |
| ------- |:-----------------:|:---:|:---:|
Curve25519 | ⏳ | ⏳ | ⏳
Ed25519 | ⏳ | ⏳ | ⏳
SM2 | ⏳ | ⏳ | ⏳
SM9 | ⏳ | ⏳ | ⏳
