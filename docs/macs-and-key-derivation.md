# MACs and key derivation

[Back to documentation](README.md)

## HMAC

Create HMAC by digest type and allocate `Length` bytes for the result:

```csharp
using System.Security.Cryptography;
using CryptoBase.Digests;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);

using var mac = HmacUtils.Create(DigestType.Sha256, key);
mac.Update("message"u8);

byte[] tag = new byte[mac.Length];
mac.GetMac(tag);
```

`GetMac` writes the tag and resets the computation while retaining the key.

## GHASH and Poly1305

| Primitive | Creation | Key | Tag |
| --- | --- | ---: | ---: |
| GHASH | `GHashUtils.Create(key)` | 16 bytes | 16 bytes |
| Poly1305 | `new Poly1305(key)` | 32 bytes | 16 bytes |

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.GHash;
using CryptoBase.Macs.Poly1305;

byte[] message = "message"u8.ToArray();

using var ghash = GHashUtils.Create(RandomNumberGenerator.GetBytes(16));
byte[] ghashTag = new byte[ghash.Length];
ghash.Update(message);
ghash.GetMac(ghashTag);

using var poly1305 = new Poly1305(RandomNumberGenerator.GetBytes(32));
byte[] poly1305Tag = new byte[poly1305.Length];
poly1305.Update(message);
poly1305.GetMac(poly1305Tag);
```

Each `Update` call zero-pads its final partial 16-byte block. Pass the input in one call, or split it only at 16-byte boundaries. `GetMac` resets the processing state.

## HKDF

The destination length determines the number of bytes produced by `DeriveKey`:

```csharp
using System.Security.Cryptography;
using CryptoBase.Digests;
using CryptoBase.KDF;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);
byte[] outputKeyMaterial = new byte[32];

Hkdf.DeriveKey(
    DigestType.Sha256,
    inputKeyMaterial,
    outputKeyMaterial,
    salt,
    "example encryption key"u8);
```

`DeriveKey` performs `Extract` and `Expand` in one call. Use those two methods separately when the intermediate pseudorandom key is needed. Output length must be between 1 and 255 times the selected digest length.
