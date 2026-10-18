# Hashes

[Back to documentation](README.md)

| Algorithm | Type |
| --- | --- |
| BLAKE2b-256 | `Blake2b256HashAlgorithm` |
| BLAKE2b-512 | `Blake2b512HashAlgorithm` |
| BLAKE3 | `Blake3HashAlgorithm` |
| MD5 | `MD5HashAlgorithm` |
| SHA-1 | `Sha1HashAlgorithm` |
| SHA-224 | `Sha224HashAlgorithm` |
| SHA-256 | `Sha256HashAlgorithm` |
| SHA-384 | `Sha384HashAlgorithm` |
| SHA-512 | `Sha512HashAlgorithm` |
| SHA3-224 | `Sha3_224HashAlgorithm` |
| SHA3-256 | `Sha3_256HashAlgorithm` |
| SHA3-384 | `Sha3_384HashAlgorithm` |
| SHA3-512 | `Sha3_512HashAlgorithm` |
| SM3 | `SM3HashAlgorithm` |
| CRC-32 | `Crc32HashAlgorithm` |
| CRC-32C | `Crc32CHashAlgorithm` |

## One-shot hashing

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;

Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

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

Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

// Get the current hash without resetting.
hasher.GetCurrentHash(hash);

// Get the current hash and reset.
hasher.GetHashAndReset(hash);

// Discard the current input.
hasher.Append("discarded"u8);
hasher.Reset();
```

## Hashing a stream

Stream hashing requires the `CryptoBase.IO` package; see [Stream and file helpers](io.md).

## BLAKE3

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

Span<byte> hash = stackalloc byte[Blake3HashAlgorithm.HashLength];

// Hash the complete input.
Blake3HashAlgorithm.HashData("hello world"u8, hash);

// Any output length works; shorter outputs are prefixes of longer ones.
byte[] extendedHash = new byte[100];
Blake3HashAlgorithm.HashData("hello world"u8, extendedHash);

// Hash on up to four threads, including the calling thread.
byte[] largeInput = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);
Blake3HashAlgorithm.HashData(largeInput, hash, maxDegreeOfParallelism: 4);
```

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

// Create an incremental hasher.
using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();

// Append input; -1 uses all processors.
byte[] largeInput = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);
hasher.Append("hello "u8);
hasher.Append(largeInput, maxDegreeOfParallelism: -1);

Span<byte> hash = stackalloc byte[Blake3HashAlgorithm.HashLength];

// Get the current hash without resetting.
hasher.GetCurrentHash(hash);

// Read 64 output bytes starting at offset 1000.
byte[] output = new byte[64];
hasher.GetCurrentHash(output, position: 1000);

// Get the current hash and reset.
hasher.GetHashAndReset(hash);
```

The stream extensions take BLAKE3 through `IHashAlgorithm<TSelf>`, so they hash in the hash mode and write the standard 32-byte hash. To hash a stream in the keyed hash or key derivation mode, or to read longer output, append its contents to an instance yourself.
