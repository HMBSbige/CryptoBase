# Data formats

[Back to documentation](README.md)

## Base32

```csharp
using System.Buffers;
using CryptoBase.DataFormatExtensions;

ReadOnlySpan<byte> data = "hello"u8;
Base32Encoding encoding = Base32Encoding.Rfc4648;
// Base32Encoding encoding = Base32Encoding.Rfc4648Hex; // Base32hex.
// Base32Encoding encoding = Base32Encoding.Rfc4648.OmitPadding; // Omit '=' padding.
// Base32Encoding encoding = Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz234567"); // Custom alphabet.
int encodedLength = encoding.GetEncodedLength(data.Length);
Span<char> encoded = stackalloc char[encodedLength];
Span<byte> decoded = stackalloc byte[Base32Encoding.GetMaxDecodedLength(encodedLength)];

// Encode to padded RFC 4648 Base32 (NBSWY3DP).
// The default isFinalBlock=true performs a complete OneShot operation.
OperationStatus encodeStatus = encoding.EncodeToChars(data, encoded, out int bytesConsumed, out int charsWritten);
OperationStatus decodeStatus = encoding.DecodeFromChars(encoded.Slice(0, charsWritten), decoded, out int charsConsumed, out int bytesWritten);

// Pass isFinalBlock=false to process complete blocks and retain an incomplete tail for the next call.

// The UTF-8 overloads use byte counts for both out pairs.
Span<byte> encodedUtf8 = stackalloc byte[encodedLength];
OperationStatus utf8EncodeStatus = encoding.EncodeToUtf8(data, encodedUtf8, out int sourceBytesConsumed, out int encodedBytesWritten);
OperationStatus utf8DecodeStatus = encoding.DecodeFromUtf8(encodedUtf8.Slice(0, encodedBytesWritten), decoded, out int encodedBytesConsumed, out int decodedBytesWritten);
```
