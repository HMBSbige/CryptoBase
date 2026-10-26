# Hashes

[Back to documentation](README.md)

| Algorithm | Type | Namespace | Output |
| --- | --- | --- | ---: |
| BLAKE2b-256 | `HashAlgorithm<Blake2b256Core>` | `CryptoBase.Hashes.Blake2` | 32 bytes |
| BLAKE2b-512 | `HashAlgorithm<Blake2b512Core>` | `CryptoBase.Hashes.Blake2` | 64 bytes |
| BLAKE3 | `Blake3HashAlgorithm` | `CryptoBase.Hashes.Blake3` | 32 bytes or any length |
| MD5 | `HashAlgorithm<MD5Core>` | `CryptoBase.Hashes.MD5` | 16 bytes |
| SHA-1 | `HashAlgorithm<Sha1Core>` | `CryptoBase.Hashes.Sha1` | 20 bytes |
| SHA-224 | `HashAlgorithm<Sha224Core>` | `CryptoBase.Hashes.Sha2` | 28 bytes |
| SHA-256 | `HashAlgorithm<Sha256Core>` | `CryptoBase.Hashes.Sha2` | 32 bytes |
| SHA-384 | `HashAlgorithm<Sha384Core>` | `CryptoBase.Hashes.Sha2` | 48 bytes |
| SHA-512 | `HashAlgorithm<Sha512Core>` | `CryptoBase.Hashes.Sha2` | 64 bytes |
| SHA3-224 | `HashAlgorithm<Sha3_224Core>` | `CryptoBase.Hashes.Sha3` | 28 bytes |
| SHA3-256 | `HashAlgorithm<Sha3_256Core>` | `CryptoBase.Hashes.Sha3` | 32 bytes |
| SHA3-384 | `HashAlgorithm<Sha3_384Core>` | `CryptoBase.Hashes.Sha3` | 48 bytes |
| SHA3-512 | `HashAlgorithm<Sha3_512Core>` | `CryptoBase.Hashes.Sha3` | 64 bytes |
| SHAKE128 | `Xof<Shake128Core>` | `CryptoBase.Hashes.Sha3` | Any length |
| SHAKE256 | `Xof<Shake256Core>` | `CryptoBase.Hashes.Sha3` | Any length |
| cSHAKE128 | `CShake128Xof` | `CryptoBase.Hashes.Sha3` | Any length |
| cSHAKE256 | `CShake256Xof` | `CryptoBase.Hashes.Sha3` | Any length |
| SM3 | `HashAlgorithm<SM3Core>` | `CryptoBase.Hashes.SM3` | 32 bytes |
| CRC-32 | `HashAlgorithm<Crc32Core>` | `CryptoBase.Hashes.Crc32` | 4 bytes |
| CRC-32C | `HashAlgorithm<Crc32CCore>` | `CryptoBase.Hashes.Crc32` | 4 bytes |

## One-shot hashing

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;

Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256Core>.HashLength];

HashAlgorithm<Sha256Core>.HashData("hello world"u8, hash);

string hex = Convert.ToHexStringLower(hash); // "b94d27b9934d3e08..."
```

## Incremental hashing

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;

using HashAlgorithm<Sha256Core> hasher = HashAlgorithm<Sha256Core>.Create();
Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256Core>.HashLength];

hasher.Append("hello "u8);
hasher.Append("world"u8);

// Get the hash of the input so far and keep appending.
hasher.GetCurrentHash(hash);
hasher.Append("!"u8);

// Get the hash and start over.
hasher.GetHashAndReset(hash);

// Discard the input so far.
hasher.Append("discarded"u8);
hasher.Reset();
```

## Generic code

`HashAlgorithm<TCore>`, `Blake3HashAlgorithm` and `PlatformSha256` implement `IHashAlgorithm<TSelf>`:

```csharp
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.SM3;
using CryptoBase.Hashes.Sha3;

static byte[] HashAll<T>(IEnumerable<byte[]> chunks) where T : class, IHashAlgorithm<T>
{
    using T hasher = T.Create();

    foreach (byte[] chunk in chunks)
    {
        hasher.Append(chunk);
    }

    byte[] hash = new byte[T.HashLength];
    hasher.GetHashAndReset(hash);
    return hash;
}

byte[][] chunks = ["hello "u8.ToArray(), "world"u8.ToArray()];
byte[] sm3 = HashAll<HashAlgorithm<SM3Core>>(chunks);
byte[] sha3 = HashAll<HashAlgorithm<Sha3_256Core>>(chunks);
```

To hash a stream or file, see [Stream and file helpers](io.md).

## Platform-backed SHA-256

`PlatformSha256` computes SHA-256 with the operating system's cryptographic library. `IsPreferredFor` tells whether it is expected to be faster than the managed implementation for a source of a given length.

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Platform;

Span<byte> hash = stackalloc byte[PlatformSha256.HashLength];
PlatformSha256.HashData("hello world"u8, hash);

// Use the faster implementation.
static int Sha256(ReadOnlySpan<byte> source, Span<byte> destination)
{
    return PlatformSha256.IsPreferredFor(source.Length)
        ? PlatformSha256.HashData(source, destination)
        : HashAlgorithm<Sha256Core>.HashData(source, destination);
}
```

## SHAKE128 and SHAKE256

`Xof<TCore>` writes as many bytes as the destination holds.

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;

byte[] output = new byte[64];
Xof<Shake256Core>.HashData("hello world"u8, output);
```

Incrementally:

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;

using Xof<Shake128Core> xof = Xof<Shake128Core>.Create();

xof.Append("hello "u8);
xof.Append("world"u8);

// Get the start of the output without changing the state; more input may follow.
byte[] prefix = new byte[32];
xof.GetCurrentHash(prefix);

// Each read continues where the previous one stopped.
byte[] first = new byte[100];
byte[] second = new byte[1000];
xof.Read(first);
xof.Read(second);

// Start over.
xof.Reset();
```

The first nonempty `Read` ends the input: until `Reset`, `Append`, `GetCurrentHash` and `GetHashAndReset` throw `InvalidOperationException`.

`Xof<TCore>`, `CShake128Xof`, `CShake256Xof` and `Blake3HashAlgorithm` implement `IXof<TSelf>`:

```csharp
using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake3;
using CryptoBase.Hashes.Sha3;

static byte[] Expand<T>(ReadOnlySpan<byte> input, int length) where T : class, IXof<T>
{
    using T xof = T.Create();
    xof.Append(input);

    byte[] output = new byte[length];
    xof.Read(output);
    return output;
}

byte[] shake = Expand<Xof<Shake256Core>>("seed"u8, 200);
byte[] cshake = Expand<CShake256Xof>("seed"u8, 200); // Create() gives SHAKE256 output
byte[] blake3 = Expand<Blake3HashAlgorithm>("seed"u8, 200);
```

## cSHAKE128 and cSHAKE256

With the function name and customization string empty, cSHAKE is SHAKE.

```csharp
using CryptoBase.Hashes.Sha3;

byte[] output = new byte[64];
CShake256Xof.HashData(functionName: [], customization: "Email Signature"u8, "hello world"u8, output);
```

Incrementally; `Reset` and `GetHashAndReset` keep the function name and customization string:

```csharp
using CryptoBase.Hashes.Sha3;

using CShake128Xof xof = CShake128Xof.Create(functionName: [], customization: "Email Signature"u8);

xof.Append("hello "u8);
xof.Append("world"u8);

byte[] first = new byte[100];
byte[] second = new byte[1000];
xof.Read(first);
xof.Read(second);
```

## BLAKE3

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

Span<byte> hash = stackalloc byte[Blake3HashAlgorithm.HashLength];
Blake3HashAlgorithm.HashData("hello world"u8, hash);

// The destination length selects the output length.
byte[] extendedHash = new byte[100];
Blake3HashAlgorithm.HashData("hello world"u8, extendedHash);

// Up to four threads, including the calling one.
byte[] largeInput = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);
Blake3HashAlgorithm.HashData(largeInput, hash, maxDegreeOfParallelism: 4);
```

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.Create();
byte[] largeInput = RandomNumberGenerator.GetBytes(64 * 1024 * 1024);

hasher.Append("hello "u8);

// -1 uses all processors.
hasher.Append(largeInput, maxDegreeOfParallelism: -1);

Span<byte> hash = stackalloc byte[Blake3HashAlgorithm.HashLength];
hasher.GetCurrentHash(hash);

// Read 64 output bytes starting at offset 1000.
byte[] output = new byte[64];
hasher.GetCurrentHash(output, position: 1000);

hasher.GetHashAndReset(hash);
```

BLAKE3's keyed hash and key derivation modes are in [MACs and key derivation](macs-and-key-derivation.md#blake3-keyed-hash). For a stream, the static `HashData` and `HashDataAsync` give only the 32-byte plain hash; for anything else, `Append` the stream to an instance.
