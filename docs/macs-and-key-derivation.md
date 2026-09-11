# MACs and key derivation

[Back to documentation](README.md)

## HMAC

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
Span<byte> tag = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLengthInBytes];

// Authenticate the complete input.
HmacAlgorithm<Sha256HashAlgorithm>.Mac(key, "message"u8, tag);

// Create an incremental HMAC instance.
using HmacAlgorithm<Sha256HashAlgorithm> mac = HmacAlgorithm<Sha256HashAlgorithm>.Create(key);

// Append input.
mac.Append("message"u8);

// Get the current MAC without resetting.
mac.GetCurrentMac(tag);

// Get the current MAC and reset while retaining the key.
mac.GetMacAndReset(tag);

// Discard the current input while retaining the key.
mac.Append("discarded"u8);
mac.Reset();
```

## Poly1305

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Poly1305;

// Generate a new one-time key for each message.
byte[] key = RandomNumberGenerator.GetBytes(Poly1305Algorithm.KeyLengthInBytes);
Span<byte> tag = stackalloc byte[Poly1305Algorithm.MacLengthInBytes];

// Authenticate the complete input.
Poly1305Algorithm.Mac(key, "message"u8, tag);
```

## HKDF

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);
ReadOnlySpan<byte> info = "example encryption key"u8;
byte[] outputKeyMaterial = new byte[32];

// Extract and expand in one call.
Hkdf.DeriveKey<Sha256HashAlgorithm>(inputKeyMaterial, outputKeyMaterial, salt, info);

Span<byte> pseudorandomKey = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLengthInBytes];

// Extract a pseudorandom key.
Hkdf.Extract<Sha256HashAlgorithm>(inputKeyMaterial, salt, pseudorandomKey);

// Expand the pseudorandom key.
Hkdf.Expand<Sha256HashAlgorithm>(pseudorandomKey, outputKeyMaterial, info);
```
