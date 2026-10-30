# Stream and file helpers

[Back to documentation](README.md)

```shell
dotnet add package CryptoBase
dotnet add package CryptoBase.IO
```

## Hashing a stream

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;

await using FileStream input = File.OpenRead(path);
byte[] hash = new byte[HashAlgorithm<Sha256Core>.HashLength];

// Each call reads the stream from its current position to the end.
// For BLAKE3, the static methods give only the 32-byte plain hash; for anything else, append the stream to an instance.
HashAlgorithm<Sha256Core>.HashData(input, hash);
await HashAlgorithm<Sha256Core>.HashDataAsync(input, hash);

using HashAlgorithm<Sha256Core> hasher = HashAlgorithm<Sha256Core>.Create();

// Mix spans and streams in one hash.
hasher.Append("header"u8);
await hasher.AppendAsync(input);
hasher.GetHashAndReset(hash);
```

## HashStream

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;

await using FileStream source = File.OpenRead(sourcePath);
await using FileStream destination = File.Create(destinationPath);
byte[] hash = new byte[HashAlgorithm<Sha256Core>.HashLength];

// Hashes every byte read from or written to the inner stream; not seekable.
// The HashStream owns the hasher; leaveOpen applies only to the inner stream.
await using HashStream<HashAlgorithm<Sha256Core>> hashing = HashStream.Create(destination, HashAlgorithm<Sha256Core>.Create(), leaveOpen: true);
await source.CopyToAsync(hashing);
hashing.GetHashAndReset(hash);
```

## Authenticating a stream

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
await using FileStream input = File.OpenRead(path);
byte[] mac = new byte[HmacAlgorithm<Sha256Core>.MacLength];

// Incremental MACs, such as HmacAlgorithm<TCore>, read streams like hashes.
HmacAlgorithm<Sha256Core>.MacData(key, input, mac);

using HmacAlgorithm<Sha256Core> hmac = HmacAlgorithm<Sha256Core>.Create(key);

// Mix spans and streams in one MAC.
hmac.Append("header"u8);
await hmac.AppendAsync(input);
hmac.GetMacAndReset(mac);
```

## MacStream

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
await using FileStream source = File.OpenRead(sourcePath);
await using FileStream destination = File.Create(destinationPath);
byte[] mac = new byte[HmacAlgorithm<Sha256Core>.MacLength];

// Like HashStream, with a MAC. Reset and GetMacAndReset keep the key.
await using MacStream<HmacAlgorithm<Sha256Core>> authenticating = MacStream.Create(destination, HmacAlgorithm<Sha256Core>.Create(key), leaveOpen: true);
await source.CopyToAsync(authenticating);
authenticating.GetMacAndReset(mac);
```

## DataUnitRandomAccess

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

// Any data-unit cipher with a 16-byte tweak, such as XtsMode<AesCipher> or XtsMode<SM4Cipher>. The file holds whole data units;
// the unit at offset n * dataUnitSize uses the tweak that XtsMode.GetTweak gives for firstDataUnitNumber + n.
// The instance owns the cipher; the handle stays open. Instances are not thread-safe: use one per thread over a shared handle.
using DataUnitRandomAccess<XtsMode<AesCipher>> xts = DataUnitRandomAccess.Create(handle, XtsMode<AesCipher>.Create(dataKey, tweakKey), dataUnitSize: 4096, leaveOpen: true);

// Write at any offset. A partial-unit write re-encrypts the whole unit, so the handle must be readable;
// a write past the end zero-pads its last unit and fills any gap with encrypted zero units.
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

```csharp
using System.Security.Cryptography;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.IO;

byte[] dataKey = RandomNumberGenerator.GetBytes(32);
byte[] tweakKey = RandomNumberGenerator.GetBytes(32);
XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(dataKey, tweakKey);

// The same layout as a seekable Stream over a seekable inner stream. The stream owns the cipher and the file stream.
using DataUnitStream<XtsMode<AesCipher>> xts = DataUnitStream.Create(File.Open(path, FileMode.OpenOrCreate), cipher, dataUnitSize: 512);

// Write at a position.
xts.Seek(1000, SeekOrigin.Begin);
xts.Write("hello world"u8);

// Read it back.
xts.Position = 1000;
byte[] buffer = new byte[11];
xts.ReadExactly(buffer);

// A changed data unit reaches the inner stream when the stream moves to another unit or is flushed or disposed;
// Length already includes it. Flush before reading the inner stream directly or opening the file elsewhere.
xts.Flush();
```
