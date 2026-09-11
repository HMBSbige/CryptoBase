# Stream ciphers

[Back to documentation](README.md)

## Direct implementations

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

// Create an XChaCha20 instance.
using XChaCha20Crypto crypto = new(key, nonce);

// Transform input and advance the stream.
crypto.Update(plaintext, ciphertext);

// Return to the initial state.
crypto.Reset();

// Apply the same stream to decrypt.
crypto.Update(ciphertext, recovered);
```

## CTR factories

| Factory | Key | IV or counter | Direction |
| --- | ---: | ---: | --- |
| `AesCtr` | 16, 24, or 32 bytes | Up to 16 bytes | Same operation |
| `SM4Ctr` | 16 bytes | Up to 16 bytes | Same operation |

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] counter = RandomNumberGenerator.GetBytes(16);
byte[] input = "message"u8.ToArray();
byte[] output = new byte[input.Length];

// Create an AES-CTR instance.
using IStreamCrypto ctr = StreamCryptoCreate.AesCtr(key, counter);

// Encrypt or decrypt with the same operation.
ctr.Update(input, output);
```
