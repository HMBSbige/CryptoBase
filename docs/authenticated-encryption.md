# Authenticated encryption

[Back to documentation](README.md)

| Type | Namespace | Key | Nonce | Tag |
| --- | --- | ---: | ---: | ---: |
| `GcmMode128<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `GcmMode128<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 16 bytes |
| `CcmMode128<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `CcmMode128<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 16 bytes |
| `Ccm8Mode128<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 8 bytes |
| `Ccm8Mode128<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 8 bytes |
| `ChaCha20Poly1305Cipher` | `CryptoBase.Ciphers.Aead` | 32 bytes | 12 bytes | 16 bytes |
| `XChaCha20Poly1305Cipher` | `CryptoBase.Ciphers.Aead` | 32 bytes | 24 bytes | 16 bytes |

`AesCipher` is in `CryptoBase.Ciphers.Blocks.Aes` and `SM4Cipher` in `CryptoBase.Ciphers.Blocks.SM4`.

## Encrypting and decrypting

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Aead;

byte[] key = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.KeySize);
byte[] plaintext = "message"u8.ToArray();
byte[] associatedData = "record header"u8.ToArray();

using XChaCha20Poly1305Cipher cipher = XChaCha20Poly1305Cipher.Create(key);

// Encrypt with a new nonce.
byte[] nonce = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.NonceSize);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[XChaCha20Poly1305Cipher.TagSize];
cipher.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

// Decrypt.
byte[] recovered = new byte[ciphertext.Length];

if (!cipher.TryDecrypt(nonce, ciphertext, tag, recovered, associatedData))
{
    // Authentication failed; recovered is cleared.
    throw new AuthenticationTagMismatchException();
}
```

## Generic code

All the types implement `IAeadCipher<TSelf>`:

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;

static byte[] Encrypt<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, out byte[] nonce, out byte[] tag) where T : IAeadCipher<T>
{
    using T cipher = T.Create(key);

    nonce = RandomNumberGenerator.GetBytes(T.NonceSize);
    tag = new byte[T.TagSize];
    byte[] ciphertext = new byte[plaintext.Length];
    cipher.Encrypt(nonce, plaintext, ciphertext, tag);
    return ciphertext;
}

byte[] sm4Ciphertext = Encrypt<CcmMode128<SM4Cipher>>(RandomNumberGenerator.GetBytes(16), "message"u8, out byte[] sm4Nonce, out byte[] sm4Tag);
byte[] chachaCiphertext = Encrypt<ChaCha20Poly1305Cipher>(RandomNumberGenerator.GetBytes(32), "message"u8, out byte[] chachaNonce, out byte[] chachaTag);
```
