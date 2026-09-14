# Stream ciphers

[Back to documentation](README.md)

## Direct implementations

| Type | Key | Nonce or IV |
| --- | ---: | ---: |
| `ChaCha20Cipher` | 32 bytes | 12 bytes |
| `ChaCha20OriginalCipher` | 16 or 32 bytes | 8 bytes |
| `XChaCha20Cipher` | 32 bytes | 24 bytes |
| `Salsa20Cipher` | 16 or 32 bytes | 8 bytes |
| `XSalsa20Cipher` | 32 bytes | 24 bytes |

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Streams;

byte[] key = RandomNumberGenerator.GetBytes(XChaCha20Cipher.KeySize);
byte[] nonce = RandomNumberGenerator.GetBytes(XChaCha20Cipher.IVSize);
byte[] plaintext = "message"u8.ToArray();
byte[] ciphertext = new byte[plaintext.Length];
byte[] recovered = new byte[ciphertext.Length];

using XChaCha20Cipher crypto = new(key, nonce);

crypto.Xor(plaintext, ciphertext);
crypto.SetCounter(0);
crypto.Xor(ciphertext, recovered);
```

## CTR

| Type | Key | IV or counter |
| --- | ---: | ---: |
| `CtrMode128<AesCipher>` | 16, 24, or 32 bytes | Exactly 16 bytes |
| `CtrMode128<SM4Cipher>` | 16 bytes | Exactly 16 bytes |

CTR increments the full 128-bit counter in big-endian order.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] counter = RandomNumberGenerator.GetBytes(16);
byte[] input = "message"u8.ToArray();
byte[] output = new byte[input.Length];

using CtrMode128<AesCipher> ctr = CtrMode128<AesCipher>.Create(key, counter);
ctr.Xor(input, output);
```
