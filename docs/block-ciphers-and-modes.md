# Block ciphers and modes

[Back to documentation](README.md)

## Block ciphers

| Type | Key |
| --- | ---: |
| `AesCipher` | 16, 24, or 32 bytes |
| `Sm4Cipher` | 16 bytes |

`Encrypt` and `Decrypt` operate on fixed-size vector buffers. This example processes one 16-byte AES block:

```csharp
using CryptoBase.Abstractions;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;

byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
byte[] plaintext = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

using AesCipher aes = AesCipher.Create(key);
var ciphertext = aes.Encrypt(plaintext.AsSpan().AsVectorBuffer16());
var recovered = aes.Decrypt(ciphertext);
```

## XTS

Create `XtsMode<TBlockCipher>` with separate data and tweak ciphers:

```csharp
using System.Security.Cryptography;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
byte[] plaintext = RandomNumberGenerator.GetBytes(512);
byte[] ciphertext = new byte[plaintext.Length];
byte[] recovered = new byte[plaintext.Length];

using var xts = new XtsMode<AesCipher>(
    AesCipher.Create(dataKey),
    AesCipher.Create(tweakKey));

Span<byte> tweak = stackalloc byte[16];
XtsMode.GetIv(tweak, dataUnitSeqNumber: 42);
xts.Encrypt(tweak, plaintext, ciphertext);
xts.Decrypt(tweak, ciphertext, recovered);
```

The input must be at least 16 bytes, the tweak must be 16 bytes, and the destination must be at least as long as the source. `GetMaxByteCount` returns the required destination size. The XTS instance owns and disposes both ciphers by default.
