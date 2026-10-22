# Data formats

[Back to documentation](README.md)

## Base32

`Base32Encoding` encodes to and decodes from `char` or UTF-8 buffers. Like `Base64`, it returns `OperationStatus` instead of throwing for bad input or short buffers.

| Instance | Alphabet | Padding |
| --- | --- | --- |
| `Base32Encoding.Rfc4648` | `A`–`Z`, `2`–`7` | `=` |
| `Base32Encoding.Rfc4648Hex` | `0`–`9`, `A`–`V` | `=` |
| `encoding.OmitPadding` | Same as `encoding` | None; padded input fails to decode |
| `Base32Encoding.Create(alphabet, padding)` | 32 distinct ASCII characters | `padding`, `=` by default |

### Encoding and decoding a whole buffer

```csharp
using System.Buffers;
using CryptoBase.Encodings;

static string ToBase32(Base32Encoding encoding, ReadOnlySpan<byte> data)
{
    char[] encoded = new char[encoding.GetEncodedLength(data.Length)];
    encoding.EncodeToChars(data, encoded, out _, out int charsWritten);
    return new string(encoded, 0, charsWritten);
}

static byte[]? FromBase32(Base32Encoding encoding, ReadOnlySpan<char> text)
{
    byte[] decoded = new byte[Base32Encoding.GetMaxDecodedLength(text.Length)];

    if (encoding.DecodeFromChars(text, decoded, out _, out int bytesWritten) is not OperationStatus.Done)
    {
        // InvalidData: a character outside the alphabet or bad padding.
        return null;
    }

    return decoded.AsSpan(0, bytesWritten).ToArray();
}

string padded = ToBase32(Base32Encoding.Rfc4648, "hello"u8); // "NBSWY3DP"
string hex = ToBase32(Base32Encoding.Rfc4648Hex, "hi"u8); // "D1KG===="
string unpadded = ToBase32(Base32Encoding.Rfc4648.OmitPadding, "hi"u8); // "NBUQ"

byte[]? data = FromBase32(Base32Encoding.Rfc4648, padded);

// A custom alphabet, here lowercase.
Base32Encoding lowercase = Base32Encoding.Create("abcdefghijklmnopqrstuvwxyz234567");
string lower = ToBase32(lowercase, "hello"u8); // "nbswy3dp"
```

`EncodeToUtf8` and `DecodeFromUtf8` do the same with UTF-8 bytes.

The source and destination must not overlap, such as two slices of one array; otherwise the output may be wrong.

### Encoding in pieces

With `isFinalBlock: false`, a call processes whole 5-byte groups (8 characters when decoding) and leaves the rest of the input unconsumed. Carry the rest over to the next call, and pass `isFinalBlock: true` with the last piece; when decoding, a group with padding is accepted only there:

```csharp
using System.Buffers;
using System.Text;
using CryptoBase.Encodings;

static void EncodeStream(Base32Encoding encoding, Stream source, TextWriter destination)
{
    byte[] input = new byte[4096];
    char[] output = new char[encoding.GetEncodedLength(input.Length)];
    int pending = 0;

    while (true)
    {
        int read = source.Read(input, pending, input.Length - pending);
        int available = pending + read;
        bool isFinalBlock = read is 0;

        OperationStatus status = encoding.EncodeToChars(input.AsSpan(0, available), output, out int consumed, out int written, isFinalBlock);
        destination.Write(output, 0, written);

        if (isFinalBlock)
        {
            return;
        }

        // NeedMoreData: carry the unconsumed tail over.
        pending = available - consumed;
        input.AsSpan(consumed, pending).CopyTo(input);
    }
}

using MemoryStream source = new(Encoding.UTF8.GetBytes("hello world"));
using StringWriter destination = new();
EncodeStream(Base32Encoding.Rfc4648, source, destination);
```
