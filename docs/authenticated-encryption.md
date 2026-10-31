# Authenticated encryption

[Back to documentation](README.md)

| Type | Namespace | Key | Nonce | Tag |
| --- | --- | ---: | ---: | ---: |
| `GcmMode<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `GcmMode<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 16 bytes |
| `CcmMode<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 16 bytes |
| `CcmMode<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 16 bytes |
| `Ccm8Mode<AesCipher>` | `CryptoBase.Ciphers.Modes` | 16, 24, or 32 bytes | 12 bytes | 8 bytes |
| `Ccm8Mode<SM4Cipher>` | `CryptoBase.Ciphers.Modes` | 16 bytes | 12 bytes | 8 bytes |
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

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;

// All the types implement IAeadCipher<TSelf>.
static byte[] Encrypt<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, out byte[] nonce, out byte[] tag) where T : IAeadCipher<T>
{
    using T cipher = T.Create(key);

    nonce = RandomNumberGenerator.GetBytes(T.NonceSize);
    tag = new byte[T.TagSize];
    byte[] ciphertext = new byte[plaintext.Length];
    cipher.Encrypt(nonce, plaintext, ciphertext, tag);
    return ciphertext;
}

byte[] sm4Ciphertext = Encrypt<CcmMode<SM4Cipher>>(RandomNumberGenerator.GetBytes(16), "message"u8, out byte[] sm4Nonce, out byte[] sm4Tag);
byte[] chachaCiphertext = Encrypt<ChaCha20Poly1305Cipher>(RandomNumberGenerator.GetBytes(32), "message"u8, out byte[] chachaNonce, out byte[] chachaTag);
```

## Chunked encryption

| Type | Namespace | Key | Overhead |
| --- | --- | ---: | ---: |
| `Cobblestone128Cipher` | `CryptoBase.Ciphers.Aead` | 16 bytes | 56 bytes + 16 per 16 KiB chunk |
| `Cobblestone256Cipher` | `CryptoBase.Ciphers.Aead` | 32 bytes | 56 bytes + 16 per 16 KiB chunk |

Cobblestone, from [c2sp.org/chunked-encryption](https://c2sp.org/chunked-encryption), takes a key and an optional context; there is no nonce to pass. For streams, files and reads at any offset, see [Stream and file helpers](io.md#chunkedencryptionstream).

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Aead;

byte[] key = RandomNumberGenerator.GetBytes(Cobblestone128Cipher.KeySize);
byte[] plaintext = "message"u8.ToArray();

// Optional. It is not stored in the message, so decryption needs the same context.
byte[] context = "message 42"u8.ToArray();

byte[] ciphertext = new byte[Cobblestone128Cipher.GetCiphertextLength(plaintext.Length)];
Cobblestone128Cipher.Encrypt(key, plaintext, ciphertext, context);

// Not every length is a valid ciphertext, so check it and get the plaintext length first.
if (!Cobblestone128Cipher.TryGetPlaintextLength(ciphertext.Length, out long length))
{
    throw new AuthenticationTagMismatchException();
}

byte[] recovered = new byte[length];

if (!Cobblestone128Cipher.TryDecrypt(key, ciphertext, recovered, context))
{
    // A wrong key or context, or a modified message; recovered is cleared.
    throw new AuthenticationTagMismatchException();
}
```
