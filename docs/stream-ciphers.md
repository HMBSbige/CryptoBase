# Stream ciphers

[Back to documentation](README.md)

Stream ciphers encrypt and decrypt with the same `Xor` call.

## ChaCha20 and Salsa20

| Type | Key | Nonce or IV | Counter |
| --- | ---: | ---: | ---: |
| `ChaCha20Cipher` | 32 bytes | 12 bytes | 32-bit |
| `ChaCha20OriginalCipher` | 16 or 32 bytes | 8 bytes | 64-bit |
| `XChaCha20Cipher` | 32 bytes | 24 bytes | 64-bit |
| `Salsa20Cipher` | 16 or 32 bytes | 8 bytes | 64-bit |
| `XSalsa20Cipher` | 32 bytes | 24 bytes | 64-bit |

A new instance starts at block counter 0.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Streams;

byte[] key = RandomNumberGenerator.GetBytes(XChaCha20Cipher.KeySize);
byte[] nonce = RandomNumberGenerator.GetBytes(XChaCha20Cipher.IVSize);
byte[] plaintext = RandomNumberGenerator.GetBytes(1000);
byte[] ciphertext = new byte[plaintext.Length];

using (XChaCha20Cipher encryptor = new(key, nonce))
{
    // Input can arrive in pieces of any length; each call continues the keystream.
    encryptor.Xor(plaintext.AsSpan(0, 100), ciphertext.AsSpan(0, 100));
    encryptor.Xor(plaintext.AsSpan(100), ciphertext.AsSpan(100));
}

using XChaCha20Cipher decryptor = new(key, nonce);

// Decrypt in place.
byte[] recovered = ciphertext.ToArray();
decryptor.Xor(recovered, recovered);

// Decrypt from block 2 (byte 128) on.
decryptor.SetCounter(2);
byte[] tail = new byte[ciphertext.Length - 128];
decryptor.Xor(ciphertext.AsSpan(128), tail);
```

`ChaCha20Cipher.GenerateBlock` computes one keystream block without an instance, such as the RFC 8439 Poly1305 key:

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Streams;

byte[] key = RandomNumberGenerator.GetBytes(ChaCha20Cipher.KeySize);
byte[] nonce = RandomNumberGenerator.GetBytes(ChaCha20Cipher.IVSize);
byte[] block = new byte[ChaCha20Cipher.BlockSize];

ChaCha20Cipher.GenerateBlock(key, nonce, counter: 0, block);
ReadOnlySpan<byte> poly1305Key = block.AsSpan(0, 32);
```

## CTR

| Type | Key | Initial counter |
| --- | ---: | ---: |
| `CtrMode128<AesCipher>` | 16, 24, or 32 bytes | 16 bytes |
| `CtrMode128<SM4Cipher>` | 16 bytes | 16 bytes |

`CtrMode128<T>` increments the whole 16-byte counter block as a big-endian number.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] initialCounter = RandomNumberGenerator.GetBytes(16);
byte[] plaintext = "message"u8.ToArray();
byte[] ciphertext = new byte[plaintext.Length];
byte[] recovered = new byte[ciphertext.Length];

using (CtrMode128<AesCipher> encryptor = CtrMode128<AesCipher>.Create(key, initialCounter))
{
    encryptor.Xor(plaintext, ciphertext);
}

using CtrMode128<AesCipher> decryptor = CtrMode128<AesCipher>.Create(key, initialCounter);
decryptor.Xor(ciphertext, recovered);
```

`Reset` restarts the keystream from a new counter block and keeps the expanded key, so one instance can handle many messages that each have their own counter, such as one per packet:

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

byte[] key = RandomNumberGenerator.GetBytes(16);
byte[][] counters = [RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(16)];
byte[][] payloads = ["first"u8.ToArray(), "second"u8.ToArray()];

using CtrMode128<AesCipher> cipher = CtrMode128<AesCipher>.Create(key, counters[0]);

for (int i = 0; i < payloads.Length; ++i)
{
    cipher.Reset(counters[i]);
    cipher.Xor(payloads[i], payloads[i]);
}
```

## Generic code

All the stream ciphers implement `IStreamCipher`:

```csharp
using CryptoBase.Abstractions.Ciphers;

static async Task XorStreamAsync(IStreamCipher cipher, Stream source, Stream destination)
{
    byte[] buffer = new byte[81920];
    int read;

    while ((read = await source.ReadAsync(buffer)) > 0)
    {
        cipher.Xor(buffer.AsSpan(0, read), buffer.AsSpan(0, read));
        await destination.WriteAsync(buffer.AsMemory(0, read));
    }
}
```
