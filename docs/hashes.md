# Hashes

[Back to documentation](README.md)

| Algorithm | Type |
| --- | --- |
| MD5 | `MD5HashAlgorithm` |
| SHA-1 | `Sha1HashAlgorithm` |
| SHA-224 | `Sha224HashAlgorithm` |
| SHA-256 | `Sha256HashAlgorithm` |
| SHA-384 | `Sha384HashAlgorithm` |
| SHA-512 | `Sha512HashAlgorithm` |
| SM3 | `SM3HashAlgorithm` |
| CRC-32 | `Crc32HashAlgorithm` |
| CRC-32C | `Crc32CHashAlgorithm` |

## One-shot hashing

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;

Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLengthInBytes];

// Hash the complete input.
HashAlgorithm<Sha256HashAlgorithm>.HashData("hello world"u8, hash);
```

## Incremental hashing

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;

// Create an incremental hasher.
using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();

// Append input.
hasher.Append("hello "u8);
hasher.Append("world"u8);

Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLengthInBytes];

// Get the current hash without resetting.
hasher.GetCurrentHash(hash);

// Get the current hash and reset.
hasher.GetHashAndReset(hash);

// Discard the current input.
hasher.Append("discarded"u8);
hasher.Reset();
```

## Hashing a stream

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;

using FileStream input = File.OpenRead(path);
Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLengthInBytes];

// Hash from the current stream position.
input.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(hash);
```

```csharp
await using FileStream input = File.OpenRead(path);
byte[] hash = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLengthInBytes];

// Hash asynchronously from the current stream position.
await input.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(hash);
```
