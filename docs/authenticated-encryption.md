# Authenticated encryption

[Back to documentation](README.md)

| Factory | Key | Nonce | Tag |
| --- | ---: | ---: | ---: |
| `AesGcm` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `SM4Gcm` | 16 bytes | 12 bytes | 16 bytes |
| `ChaCha20Poly1305` | 32 bytes | 12 bytes | 16 bytes |
| `XChaCha20Poly1305` | 32 bytes | 24 bytes | 16 bytes |

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AeadCryptos;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] plaintext = "message"u8.ToArray();
byte[] associatedData = "record header"u8.ToArray();

// Create an XChaCha20-Poly1305 instance.
using IAeadCrypto crypto = AeadCryptoCreate.XChaCha20Poly1305(key);

// Use a unique nonce for each encryption with the same key.
byte[] nonce = RandomNumberGenerator.GetBytes(crypto.NonceSizeInBytes);
byte[] ciphertext = new byte[crypto.GetCiphertextSizeInBytes(plaintext.Length)];
byte[] tag = new byte[crypto.TagSizeInBytes];

// Encrypt and write the ciphertext and tag separately.
crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

byte[] recovered = new byte[crypto.GetPlaintextSizeInBytes(ciphertext.Length)];

// Authenticate and decrypt; failure throws AuthenticationTagMismatchException without changing recovered.
crypto.Decrypt(nonce, ciphertext, tag, recovered, associatedData);
```
