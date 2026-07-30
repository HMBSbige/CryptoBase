# Data formats

[Back to documentation](README.md)

The `CryptoBase.DataFormatExtensions` namespace provides Base32 and hexadecimal conversion helpers.

## Base32

`ToBase32String` produces uppercase, padded RFC 4648 Base32. `FromBase32String` accepts the uppercase RFC 4648 alphabet with optional trailing `=` padding.

```csharp
using CryptoBase.DataFormatExtensions;

ReadOnlySpan<byte> data = "hello"u8;

string encoded = data.ToBase32String(); // NBSWY3DP
byte[] decoded = encoded.FromBase32String();
```

## Hexadecimal

`ToHex` returns lowercase text, while `ToHexString` returns uppercase text. `FromHex` accepts either case and follows `Convert.FromHexString` validation rules.

```csharp
using CryptoBase.DataFormatExtensions;

ReadOnlySpan<byte> data = "hello"u8;

string lower = data.ToHex();       // 68656c6c6f
string upper = data.ToHexString(); // 68656C6C6F
byte[] decoded = upper.FromHex();
```
