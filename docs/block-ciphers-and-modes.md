# Block ciphers and modes

[Back to documentation](README.md)

## Block ciphers

| Type | Key |
| --- | ---: |
| `AesCipher` | 16, 24, or 32 bytes |
| `SM4Cipher` | 16 bytes |

```csharp
using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Vectors;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;

byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
byte[] plaintext = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
VectorBuffer16 plaintextBlock = plaintext.AsSpan().AsVectorBuffer16();

// Create an AES cipher.
using AesCipher aes = AesCipher.Create(key);

// Encrypt one 16-byte block.
VectorBuffer16 ciphertext = aes.Encrypt(plaintextBlock);

// Decrypt one 16-byte block.
VectorBuffer16 recovered = aes.Decrypt(ciphertext);
```

## XTS

```csharp
using System.Security.Cryptography;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
byte[] plaintext = RandomNumberGenerator.GetBytes(512);

// Create XTS with separate data and tweak ciphers.
using XtsMode<AesCipher> xts = new(AesCipher.Create(dataKey), AesCipher.Create(tweakKey));

// Allocate output buffers.
byte[] ciphertext = new byte[xts.GetMaxByteCount(plaintext.Length)];
byte[] recovered = new byte[xts.GetMaxByteCount(ciphertext.Length)];

// Create the tweak input from a data-unit sequence number.
Span<byte> tweak = stackalloc byte[16];
XtsMode.GetIV(tweak, dataUnitSeqNumber: 42);

// Encrypt the data unit.
xts.Encrypt(tweak, plaintext, ciphertext);

// Decrypt the data unit.
xts.Decrypt(tweak, ciphertext, recovered);
```
