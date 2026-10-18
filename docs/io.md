# Stream and file helpers

[Back to documentation](README.md)

## Installation

`CryptoBase.IO` depends only on `CryptoBase.Abstractions`. The algorithms come from `CryptoBase`.

```shell
dotnet add package CryptoBase
dotnet add package CryptoBase.IO
```

## Hashing a stream

Each call reads the stream from its current position to the end.

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;

using FileStream input = File.OpenRead(path);
Span<byte> hash = stackalloc byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

HashAlgorithm<Sha256HashAlgorithm>.HashData(input, hash);
```

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;

await using FileStream input = File.OpenRead(path);
byte[] hash = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

await HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(input, hash);
```

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;

await using FileStream input = File.OpenRead(path);
byte[] hash = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();

// Mix spans and streams in one hash.
hasher.Append("header"u8);
await hasher.AppendAsync(input);
hasher.GetHashAndReset(hash);
```

## HashStream

`HashStream` hashes every byte read from or written to the inner stream. It is not seekable. It owns the hasher; `leaveOpen` applies only to the inner stream.

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;

await using FileStream source = File.OpenRead(sourcePath);
await using FileStream destination = File.Create(destinationPath);
byte[] hash = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];

// Hash while copying; the stream disposes the hasher.
await using HashStream<HashAlgorithm<Sha256HashAlgorithm>> hashing = HashStream.Create(destination, HashAlgorithm<Sha256HashAlgorithm>.Create(), leaveOpen: true);
await source.CopyToAsync(hashing);
hashing.GetHashAndReset(hash);
```

## DataUnitRandomAccess

`DataUnitRandomAccess` encrypts a file at arbitrary offsets with a data-unit cipher that uses a 16-byte tweak, such as `XtsMode<AesCipher>`. The file holds whole data units, so its length must be a multiple of the data unit size. The unit at offset `n * dataUnitSize` uses the little-endian 128-bit tweak `firstDataUnitNumber + n`, the same numbering as `XtsMode.GetIV`.

Writes past the end zero-pad their last unit and fill any gap with encrypted zero units. A write that covers part of a unit reads and re-encrypts that unit, so the handle must be readable. The instance owns the cipher. Instances are not thread-safe; for parallel access, create one instance per thread over a shared handle with `leaveOpen: true`. `XtsMode<SM4Cipher>` from `CryptoBase.Ciphers.Blocks.SM4` works the same way.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;
using Microsoft.Win32.SafeHandles;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
byte[] plaintext = RandomNumberGenerator.GetBytes(10000);

using SafeFileHandle handle = File.OpenHandle(path, FileMode.OpenOrCreate, FileAccess.ReadWrite);

// The instance owns the cipher; the handle stays open.
using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(dataKey, tweakKey), dataUnitSize: 4096, leaveOpen: true);

// Encrypt and write at any offset.
xts.Write(plaintext, offset: 100);

// Read and decrypt at any offset.
byte[] buffer = new byte[plaintext.Length];
int read = xts.Read(buffer, offset: 100);

// Asynchronous forms.
await xts.WriteAsync(plaintext, offset: 20000);
read = await xts.ReadAsync(buffer, offset: 20000);

// Lengths are multiples of the data unit size.
xts.SetLength(8192);

// Flush data and metadata to disk.
xts.Flush();
```

## DataUnitStream

`DataUnitStream` exposes the same layout as a seekable `Stream`. It requires a seekable inner stream. Its `Length` is the inner stream's length, extended by a changed data unit that has not been written yet.

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(dataKey, tweakKey);

// The stream owns the cipher and the file stream.
using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(File.Open(path, FileMode.OpenOrCreate), cipher, dataUnitSize: 512);

// Write at a position.
xts.Seek(1000, SeekOrigin.Begin);
xts.Write("hello world"u8);

// Read it back.
xts.Position = 1000;
byte[] buffer = new byte[11];
xts.ReadExactly(buffer);
```

`DataUnitStream` keeps the plaintext of the data unit that the last partial read or write touched, so small sequential reads and writes decrypt and encrypt each unit once. A changed unit reaches the inner stream when the stream moves to another unit, reads outside it, or is flushed or disposed. Call `Flush` before reading the inner stream directly or opening the file elsewhere. Reads and writes of whole aligned units go straight to the inner stream.
