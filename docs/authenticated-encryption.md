# Authenticated encryption

[Back to documentation](README.md)

| Type | Key | Nonce | Tag |
| --- | ---: | ---: | ---: |
| `GcmMode128<AesCipher>` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `GcmMode128<SM4Cipher>` | 16 bytes | 12 bytes | 16 bytes |
| `ChaCha20Poly1305Cipher` | 32 bytes | 12 bytes | 16 bytes |
| `XChaCha20Poly1305Cipher` | 32 bytes | 24 bytes | 16 bytes |

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Aead;

byte[] key = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.KeySize);
byte[] plaintext = "message"u8.ToArray();
byte[] associatedData = "record header"u8.ToArray();

using XChaCha20Poly1305Cipher crypto = XChaCha20Poly1305Cipher.Create(key);

// Use a unique nonce for each encryption with the same key.
byte[] nonce = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.NonceSize);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[XChaCha20Poly1305Cipher.TagSize];

crypto.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

byte[] recovered = new byte[ciphertext.Length];

// On authentication failure, TryDecrypt clears the output prefix and returns false.
if (!crypto.TryDecrypt(nonce, ciphertext, tag, recovered, associatedData))
{
    throw new AuthenticationTagMismatchException();
}
```
