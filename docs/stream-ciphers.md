# Stream ciphers

[Back to documentation](README.md)

`IStreamCrypto.Update` writes the transformed input to a destination of at least the same length. Successive calls continue the current stream; `Reset` returns to its initial state.

## ChaCha, Salsa, and RC4 implementations

Create these algorithms directly:

| Type | Key | Nonce or IV |
| --- | ---: | ---: |
| `ChaCha20Crypto` | 32 bytes | 12 bytes |
| `ChaCha20OriginalCrypto` | 16 or 32 bytes | 8 bytes |
| `XChaCha20Crypto` | 32 bytes | 24 bytes |
| `Salsa20Crypto` | 16 or 32 bytes | 8 bytes |
| `XSalsa20Crypto` | 32 bytes | 24 bytes |
| `RC4Crypto` | Non-empty | None |

```csharp
using System.Security.Cryptography;
using CryptoBase.SymmetricCryptos.StreamCryptos;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] nonce = RandomNumberGenerator.GetBytes(24);
byte[] plaintext = "message"u8.ToArray();
byte[] ciphertext = new byte[plaintext.Length];
byte[] recovered = new byte[ciphertext.Length];

using var crypto = new XChaCha20Crypto(key, nonce);
crypto.Update(plaintext, ciphertext);

crypto.Reset();
crypto.Update(ciphertext, recovered);
```

## CTR and CFB factories

`StreamCryptoCreate` creates streaming modes over the built-in AES and SM4 block ciphers:

| Factory | Key | IV or counter | Direction |
| --- | ---: | ---: | --- |
| `AesCtr` | 16, 24, or 32 bytes | Up to 16 bytes | Same operation for encrypt/decrypt |
| `Sm4Ctr` | 16 bytes | Up to 16 bytes | Same operation for encrypt/decrypt |
| `AesCfb` | 16, 24, or 32 bytes | Exactly 16 bytes | Set with `isEncrypt` |
| `Sm4Cfb` | 16 bytes | Exactly 16 bytes | Set with `isEncrypt` |

Short CTR values occupy the leading bytes of the 16-byte counter block and are followed by zeros. Both CFB factories use CFB-128.

```csharp
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;

byte[] key = new byte[32];
byte[] initialCounter = new byte[16];
byte[] input = "message"u8.ToArray();
byte[] output = new byte[input.Length];

using IStreamCrypto crypto = StreamCryptoCreate.AesCtr(key, initialCounter);
crypto.Update(input, output);
```

CTR uses the same `Update` call for encryption and decryption. For CFB, create separate instances with `isEncrypt: true` and `isEncrypt: false`.
