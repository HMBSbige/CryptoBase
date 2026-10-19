# Hashes

[Back to documentation](README.md)

| Algorithm | Type |
| --- | --- |
| BLAKE2b-256 | `Blake2b256HashAlgorithm` |
| BLAKE2b-512 | `Blake2b512HashAlgorithm` |
| BLAKE3 | `Blake3HashAlgorithm` (also an XOF) |
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
| SHAKE128 | `Shake128HashAlgorithm` (with `Xof<TCore>`) |
| SHAKE256 | `Shake256HashAlgorithm` (with `Xof<TCore>`) |
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

## Extendable-output functions

SHAKE128 and SHAKE256 are extendable-output functions (XOFs): the output is a stream of any length, and a shorter output is a prefix of every longer one. `Xof<TCore>` provides them; the destination length selects the output length. For their full strength, read at least 32 bytes from SHAKE128 and 64 bytes from SHAKE256.

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;

byte[] output = new byte[64];

// Hash the complete input.
Xof<Shake256HashAlgorithm>.HashData("hello world"u8, output);
```

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;

// Create an incremental XOF.
using Xof<Shake128HashAlgorithm> xof = Xof<Shake128HashAlgorithm>.Create();

// Append input.
xof.Append("hello "u8);
xof.Append("world"u8);

// Get the start of the output without changing the state.
byte[] prefix = new byte[32];
xof.GetCurrentHash(prefix);

// Read the output in pieces; each read continues where the previous one stopped.
byte[] first = new byte[100];
byte[] second = new byte[1000];
xof.Read(first);
xof.Read(second);

// Discard the input and start over.
xof.Reset();
```

The first nonempty `Read` ends the input; until `Reset`, `Append`, `GetCurrentHash` and `GetHashAndReset` throw `InvalidOperationException`.

`Blake3HashAlgorithm` implements `IXof<TSelf>` too, so generic code can take either:

```csharp
using CryptoBase.Abstractions.Hashes;

static void Expand<T>(ReadOnlySpan<byte> input, Span<byte> output) where T : class, IXof<T>
{
	using T xof = T.Create();
	xof.Append(input);
	xof.Read(output);
}
```

The stream extensions of `CryptoBase.IO` take only `IHashAlgorithm<TSelf>`, so to feed a stream to an XOF, append its contents yourself.

## Hashing a stream

Stream hashing requires the `CryptoBase.IO` package; see [Stream and file helpers](io.md).

## Platform-backed SHA-256

`PlatformSha256` computes SHA-256 with the operating system's cryptographic library. It implements `IHashAlgorithm<TSelf>`, so it can replace `HashAlgorithm<Sha256HashAlgorithm>` in generic code and `HashStream<T>`. `IsPreferred` is `true` on x86 and x64 processors with the SHA extensions, where it is faster than the managed implementation.

```csharp
using CryptoBase.Platform;

Span<byte> hash = stackalloc byte[PlatformSha256.HashLength];

// Hash the complete input.
PlatformSha256.HashData("hello world"u8, hash);
```

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
