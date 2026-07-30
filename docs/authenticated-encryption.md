# Authenticated encryption

[Back to documentation](README.md)

Use `AEADCryptoCreate` to create an `IAEADCrypto` implementation.

## Algorithms and sizes

| Factory | Key | Nonce | Tag |
| --- | ---: | ---: | ---: |
| `AesGcm` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `Sm4Gcm` | 16 bytes | 12 bytes | 16 bytes |
| `ChaCha20Poly1305` | 32 bytes | 12 bytes | 16 bytes |
| `XChaCha20Poly1305` | 32 bytes | 24 bytes | 16 bytes |

## Usage

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] nonce = RandomNumberGenerator.GetBytes(24);
byte[] plaintext = "message"u8.ToArray();
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16];

using IAEADCrypto crypto = AEADCryptoCreate.XChaCha20Poly1305(key);
crypto.Encrypt(nonce, plaintext, ciphertext, tag, "record header"u8);

byte[] recovered = new byte[ciphertext.Length];
crypto.Decrypt(nonce, ciphertext, tag, recovered, "record header"u8);
```

The plaintext and ciphertext buffers must have the same length. Associated data is optional; pass the same value to `Decrypt`. A mismatched ciphertext, nonce, tag, or associated-data value causes `Decrypt` to throw `AuthenticationTagMismatchException`.
