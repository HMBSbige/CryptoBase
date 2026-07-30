# Digests

[Back to documentation](README.md)

Use `DigestUtils.Create` to create an `IHash` implementation.

## Supported algorithms

`DigestUtils.Create` supports `Sm3`, `Md5`, `Sha1`, `Sha256`, `Sha384`, `Sha512`, `Crc32`, and `Crc32C`.

## Incremental hashing

Allocate `Length` bytes for the result. Pass preceding input to `Update` and the final segment to `UpdateFinal`:

```csharp
using CryptoBase.Digests;

using var hasher = DigestUtils.Create(DigestType.Sha256);
byte[] digest = new byte[hasher.Length];

hasher.Update("hello "u8);
hasher.UpdateFinal("world"u8, digest);
```

Call `GetHash` when all input has already been passed to `Update`. `GetHash` and `UpdateFinal` reset the accumulated state; `Reset` discards it without producing a digest.

## Hashing a stream

`ComputeHashAsync` reads from the stream's current position and returns the digest:

```csharp
using CryptoBase.Digests;

static async Task<byte[]> HashFileAsync(string path)
{
    await using FileStream input = File.OpenRead(path);
    using var hasher = DigestUtils.Create(DigestType.Sha256);
    return await hasher.ComputeHashAsync(input);
}
```
