# Block ciphers and modes

[Back to documentation](README.md)

## Block ciphers

| Type | Namespace | Key | Block |
| --- | --- | ---: | ---: |
| `AesCipher` | `CryptoBase.Ciphers.Blocks.Aes` | 16, 24, or 32 bytes | 16 bytes |
| `SM4Cipher` | `CryptoBase.Ciphers.Blocks.SM4` | 16 bytes | 16 bytes |

```csharp
using CryptoBase.Ciphers.Blocks.Aes;

byte[] key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
byte[] plaintext = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
Span<byte> ciphertext = stackalloc byte[AesCipher.BlockSize];
Span<byte> recovered = stackalloc byte[AesCipher.BlockSize];

using AesCipher aes = AesCipher.Create(key);

// One block.
aes.EncryptBlock(plaintext, ciphertext);
aes.DecryptBlock(ciphertext, recovered);

// Several blocks at once; the length must be a multiple of the block size.
byte[] blocks = new byte[4 * AesCipher.BlockSize];
aes.EncryptBlocks(blocks, blocks);
aes.DecryptBlocks(blocks, blocks);
```

## XTS

`XtsMode<AesCipher>` and `XtsMode<SM4Cipher>` take data units of at least 16 bytes, not necessarily whole blocks.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);

// Separate data and tweak keys of equal length.
using XtsMode<AesCipher> xts = XtsMode<AesCipher>.Create(dataKey, tweakKey);

// Or one key: the data key followed by the tweak key.
byte[] combinedKey = [.. dataKey, .. tweakKey];
using XtsMode<AesCipher> sameXts = XtsMode<AesCipher>.Create(combinedKey);

// Encrypt sector 42 of a disk image.
byte[] sector = RandomNumberGenerator.GetBytes(512);
Span<byte> tweak = stackalloc byte[XtsMode<AesCipher>.TweakSize];
XtsMode.GetIV(tweak, dataUnitSeqNumber: 42);

byte[] ciphertext = new byte[sector.Length];
xts.Encrypt(tweak, sector, ciphertext);

// Decrypt in place.
xts.Decrypt(tweak, ciphertext, ciphertext);
```

To encrypt files and streams, see [Stream and file helpers](io.md).

## Padding

`SymmetricPadding` applies and removes every `PaddingMode`.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Padding;

byte[] plaintext = "Hello"u8.ToArray();
const int blockSize = 16;
const PaddingMode mode = PaddingMode.PKCS7;

// Pad.
byte[] padded = new byte[SymmetricPadding.GetPaddedLength(plaintext.Length, blockSize, mode)];
int written = SymmetricPadding.Pad(plaintext, padded, blockSize, mode);

// Unpad.
if (!SymmetricPadding.TryGetUnpaddedLength(padded.AsSpan(0, written), blockSize, mode, out int length))
{
    throw new CryptographicException("Invalid padding.");
}

ReadOnlySpan<byte> recovered = padded.AsSpan(0, length);
```

`Zeros` leaves aligned input unchanged and `None` requires it; for both, `TryGetUnpaddedLength` keeps the whole input.
