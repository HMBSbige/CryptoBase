# MACs and key derivation

[Back to documentation](README.md)

## HMAC

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
Span<byte> tag = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

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
Span<byte> tag = stackalloc byte[Poly1305Algorithm.MacLength];

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

Span<byte> pseudorandomKey = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

// Extract a pseudorandom key.
Hkdf.Extract<Sha256HashAlgorithm>(inputKeyMaterial, salt, pseudorandomKey);

// Expand the pseudorandom key.
Hkdf.Expand<Sha256HashAlgorithm>(pseudorandomKey, outputKeyMaterial, info);
```

## Argon2id

```csharp
using System.Security.Cryptography;
using System.Text;
using CryptoBase.Kdf;

byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[] tag = new byte[32];

// Use RFC 9106's second recommended option: m = 64 MiB, t = 3, p = 4.
Argon2id.DeriveKey(password, salt, tag, Argon2Parameters.Rfc9106SecondRecommended);

// Fill the four lanes on the calling thread only. The tag is the same.
Argon2id.DeriveKey(password, salt, tag, Argon2Parameters.Rfc9106SecondRecommended, maxDegreeOfParallelism: 1);

// Choose custom costs, here OWASP's recommended minimum for Argon2id.
Argon2Parameters parameters = new(memorySizeInKibibytes: 19 * 1024, iterations: 2, parallelism: 1);
Argon2id.DeriveKey(password, salt, tag, parameters);

// Add a secret key (pepper) and associated data.
byte[] secret = RandomNumberGenerator.GetBytes(32);
Argon2id.DeriveKey(password, salt, tag, parameters, secret, "user-id"u8);
```
