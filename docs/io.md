# Stream and file helpers

[Back to documentation](README.md)

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

// Hash while copying.
await using HashStream<HashAlgorithm<Sha256HashAlgorithm>> hashing = HashStream.Create(destination, HashAlgorithm<Sha256HashAlgorithm>.Create(), leaveOpen: true);
await source.CopyToAsync(hashing);
hashing.GetHashAndReset(hash);
```

## Authenticating a stream

Incremental MACs, such as `HmacAlgorithm<THash>`, read streams the same way.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
using FileStream input = File.OpenRead(path);
Span<byte> mac = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

HmacAlgorithm<Sha256HashAlgorithm>.MacData(key, input, mac);
```

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
await using FileStream input = File.OpenRead(path);
byte[] mac = new byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];
using HmacAlgorithm<Sha256HashAlgorithm> hmac = HmacAlgorithm<Sha256HashAlgorithm>.Create(key);

// Mix spans and streams in one MAC.
hmac.Append("header"u8);
await hmac.AppendAsync(input);
hmac.GetMacAndReset(mac);
```

## MacStream

`MacStream` does the same as `HashStream` with a MAC. `Reset` and `GetMacAndReset` keep the key.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
await using FileStream source = File.OpenRead(sourcePath);
await using FileStream destination = File.Create(destinationPath);
byte[] mac = new byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

// Authenticate while copying.
await using MacStream<HmacAlgorithm<Sha256HashAlgorithm>> authenticating = MacStream.Create(destination, HmacAlgorithm<Sha256HashAlgorithm>.Create(key), leaveOpen: true);
await source.CopyToAsync(authenticating);
authenticating.GetMacAndReset(mac);
```

## DataUnitRandomAccess

`DataUnitRandomAccess` encrypts a file at any offset with a data-unit cipher that uses a 16-byte tweak, such as `XtsMode<AesCipher>` or `XtsMode<SM4Cipher>`. The file holds whole data units only. The unit at offset `n * dataUnitSize` uses the tweak that `XtsMode.GetIV` gives for `firstDataUnitNumber + n`.

Writes past the end zero-pad their last unit and fill any gap with encrypted zero units. A partial-unit write re-encrypts the whole unit, so the handle must be readable. Instances are not thread-safe; for parallel access, create one instance per thread over a shared handle with `leaveOpen: true`.

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

// Write at any offset.
xts.Write(plaintext, offset: 100);

// Read at any offset.
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

`DataUnitStream` exposes the same layout as a seekable `Stream` over a seekable inner stream. Its `Length` includes a changed data unit that has not been written yet.

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

A changed data unit reaches the inner stream when the stream moves to another unit or is flushed or disposed. Call `Flush` before reading the inner stream directly or opening the file elsewhere.
