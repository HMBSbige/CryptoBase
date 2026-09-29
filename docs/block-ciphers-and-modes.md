# Block ciphers and modes

[Back to documentation](README.md)

## Block ciphers

| Type | Key |
| --- | ---: |
| `AesCipher` | 16, 24, or 32 bytes |
| `SM4Cipher` | 16 bytes |

```csharp
using CryptoBase.Ciphers.Blocks.Aes;

byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
byte[] plaintext = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
Span<byte> ciphertext = stackalloc byte[16];
Span<byte> recovered = stackalloc byte[16];

// Create an AES cipher.
using AesCipher aes = AesCipher.Create(key);

// Encrypt one 16-byte block.
aes.EncryptBlock(plaintext, ciphertext);

// Decrypt one 16-byte block.
aes.DecryptBlock(ciphertext, recovered);
```

## Padding

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Padding;

byte[] plaintext = "Hello"u8.ToArray();
const int blockSize = 16;
const PaddingMode mode = PaddingMode.PKCS7;

// Pad the input.
byte[] padded = new byte[SymmetricPadding.GetPaddedLength(plaintext.Length, blockSize, mode)];
int written = SymmetricPadding.Pad(plaintext, padded, blockSize, mode);

// Validate and remove padding.
if (!SymmetricPadding.TryGetUnpaddedLength(padded.AsSpan(0, written), blockSize, mode, out int length))
{
    throw new CryptographicException("Invalid padding.");
}

ReadOnlySpan<byte> recovered = padded.AsSpan(0, length);
```

## XTS

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Blocks.Aes;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
byte[] plaintext = RandomNumberGenerator.GetBytes(512);

// Create XTS with separate data and tweak keys.
using XtsMode<AesCipher> xts = XtsMode<AesCipher>.Create(dataKey, tweakKey);

// Allocate output buffers.
byte[] ciphertext = new byte[plaintext.Length];
byte[] recovered = new byte[ciphertext.Length];

// Create the tweak input from a data-unit sequence number.
Span<byte> tweak = stackalloc byte[16];
XtsMode.GetIV(tweak, dataUnitSeqNumber: 42);

// Encrypt the data unit.
xts.Encrypt(tweak, plaintext, ciphertext);

// Decrypt the data unit.
xts.Decrypt(tweak, ciphertext, recovered);
```
