# MACs and key derivation

[Back to documentation](README.md)

| Algorithm | Type | Namespace |
| --- | --- | --- |
| HMAC | `HmacAlgorithm<TCore>` | `CryptoBase.Macs.Hmac` |
| HMAC-SHA256 | `PlatformHmacSha256` | `CryptoBase.Platform` |
| Poly1305 | `Poly1305Algorithm` | `CryptoBase.Macs.Poly1305` |
| BLAKE3 keyed hash and key derivation | `Blake3HashAlgorithm` | `CryptoBase.Hashes.Blake3` |
| KMAC128, KMAC256 | `Kmac128Algorithm`, `Kmac256Algorithm` | `CryptoBase.Macs.Kmac` |
| KMACXOF128, KMACXOF256 | `KmacXof128Algorithm`, `KmacXof256Algorithm` | `CryptoBase.Macs.Kmac` |
| HKDF | `Hkdf`, `Hkdf<TMac>` | `CryptoBase.Kdf` |
| TLS 1.2 PRF | `Tls12Prf`, `Tls12Prf<TMac>` | `CryptoBase.Kdf` |
| Argon2 | `Argon2id`, `Argon2i`, `Argon2d`, `Argon2PasswordHasher` | `CryptoBase.Kdf` |

## HMAC

`TCore` is the type argument of any `HashAlgorithm<T>` in [Hashes](hashes.md) except CRC-32 and CRC-32C.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] tag = new byte[HmacAlgorithm<Sha256Core>.MacLength];

HmacAlgorithm<Sha256Core>.Mac(key, "message"u8, tag);

// Incrementally.
using HmacAlgorithm<Sha256Core> mac = HmacAlgorithm<Sha256Core>.Create(key);

mac.Append("mess"u8);
mac.Append("age"u8);

// Get the MAC of the input so far and keep appending.
mac.GetCurrentMac(tag);

// Get the MAC and start over with the same key.
mac.GetMacAndReset(tag);

// Discard the input so far.
mac.Append("discarded"u8);
mac.Reset();
```

To check a received tag:

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Macs.Hmac;

static bool IsValid(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> receivedTag)
{
    Span<byte> expected = stackalloc byte[HmacAlgorithm<Sha256Core>.MacLength];
    HmacAlgorithm<Sha256Core>.Mac(key, message, expected);
    return CryptographicOperations.FixedTimeEquals(expected, receivedTag);
}
```

To authenticate a stream or file, see [Stream and file helpers](io.md#authenticating-a-stream).

## Platform-backed HMAC-SHA256

`PlatformHmacSha256` computes HMAC-SHA256 with the operating system's cryptographic library. `IsPreferredFor` tells whether it is expected to be faster than the managed implementation for a message of a given length.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;

byte[] key = RandomNumberGenerator.GetBytes(32);
Span<byte> tag = stackalloc byte[PlatformHmacSha256.MacLength];

PlatformHmacSha256.Mac(key, "message"u8, tag);

using PlatformHmacSha256 mac = PlatformHmacSha256.Create(key);
mac.Append("message"u8);
mac.GetMacAndReset(tag);

// Use the faster implementation.
static int HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
{
    return PlatformHmacSha256.IsPreferredFor(source.Length)
        ? PlatformHmacSha256.Mac(key, source, destination)
        : HmacAlgorithm<Sha256Core>.Mac(key, source, destination);
}
```

## Poly1305

`Poly1305Algorithm` is one-shot only.

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Poly1305;

byte[] key = RandomNumberGenerator.GetBytes(Poly1305Algorithm.KeyLengthInBytes);
Span<byte> tag = stackalloc byte[Poly1305Algorithm.MacLength];

Poly1305Algorithm.Mac(key, "message"u8, tag);
```

## BLAKE3 keyed hash

The destination length selects the tag length.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

byte[] key = RandomNumberGenerator.GetBytes(Blake3HashAlgorithm.KeyLengthInBytes);
Span<byte> tag = stackalloc byte[Blake3HashAlgorithm.HashLength];

Blake3HashAlgorithm.KeyedHashData(key, "message"u8, tag);

// Incrementally; GetHashAndReset keeps the key.
using Blake3HashAlgorithm mac = Blake3HashAlgorithm.CreateKeyed(key);
mac.Append("message"u8);
mac.GetHashAndReset(tag);
```

## KMAC

The destination length selects the tag length; a truncated tag is not the shorter tag.

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Kmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] tag = new byte[32];

Kmac256Algorithm.Mac(key, "message"u8, tag);

// Each customization string gives unrelated tags under the same key.
Kmac256Algorithm.Mac(key, "message"u8, tag, customization: "example v1 session tokens"u8);

// Reset and GetMacAndReset keep the key and customization string.
using Kmac256Algorithm mac = Kmac256Algorithm.Create(key, customization: "example v1 session tokens"u8);

mac.Append("mess"u8);
mac.Append("age"u8);
mac.GetCurrentMac(tag);
mac.GetMacAndReset(tag);
```

To check a received tag, compute it at the length the protocol fixes:

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Kmac;

static bool IsValid(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> receivedTag)
{
    Span<byte> expected = stackalloc byte[32];
    Kmac256Algorithm.Mac(key, message, expected);
    return CryptographicOperations.FixedTimeEquals(expected, receivedTag);
}
```

`KmacXof128Algorithm` and `KmacXof256Algorithm` compute KMACXOF, whose output is a stream.

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Kmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] output = new byte[64];

KmacXof256Algorithm.HashData(key, "message"u8, output, customization: "example v1 key stream"u8);

using KmacXof256Algorithm xof = KmacXof256Algorithm.Create(key, customization: "example v1 key stream"u8);
xof.Append("message"u8);

byte[] first = new byte[32];
byte[] second = new byte[32];
xof.Read(first);
xof.Read(second);
```

## HKDF

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;

byte[] sharedSecret = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);

// Derive two independent keys from one secret by varying info.
byte[] encryptionKey = new byte[32];
byte[] macKey = new byte[32];
Hkdf.DeriveKey<Sha256Core>(sharedSecret, encryptionKey, salt, "example v1 encryption"u8);
Hkdf.DeriveKey<Sha256Core>(sharedSecret, macKey, salt, "example v1 mac"u8);

// The same in two steps: extract once, then expand for each key.
Span<byte> pseudorandomKey = stackalloc byte[HmacAlgorithm<Sha256Core>.MacLength];
Hkdf.Extract<Sha256Core>(sharedSecret, salt, pseudorandomKey);
Hkdf.Expand<Sha256Core>(pseudorandomKey, encryptionKey, "example v1 encryption"u8);
Hkdf.Expand<Sha256Core>(pseudorandomKey, macKey, "example v1 mac"u8);
```

The destination length selects the output length, from 1 byte to 255 times the hash length. `salt` and `info` may be empty.

## TLS 1.2 PRF

The overload with two seed parts takes `seed1 || seed2` without concatenating them.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;

byte[] preMasterSecret = RandomNumberGenerator.GetBytes(48);
byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
byte[] serverRandom = RandomNumberGenerator.GetBytes(32);
byte[] masterSecret = new byte[48];
byte[] keyBlock = new byte[128];

// Master secret.
Tls12Prf.DeriveKey<Sha256Core>(preMasterSecret, "master secret"u8, clientRandom, serverRandom, masterSecret);

// Key block.
Tls12Prf.DeriveKey<Sha256Core>(masterSecret, "key expansion"u8, serverRandom, clientRandom, keyBlock);

// Extended master secret (RFC 7627).
byte[] sessionHash = SHA256.HashData("handshake messages"u8);
Tls12Prf.DeriveKey<Sha256Core>(preMasterSecret, "extended master secret"u8, sessionHash, masterSecret);
```

## HKDF and TLS 1.2 PRF over a chosen HMAC implementation

`Hkdf<TMac>` and `Tls12Prf<TMac>` have the same methods, with the HMAC as the type argument, such as `PlatformHmacSha256`. The constraint admits any `IMacAlgorithm<TSelf>`, but only an HMAC is valid.

```csharp
using System.Security.Cryptography;
using CryptoBase.Kdf;
using CryptoBase.Platform;

byte[] sharedSecret = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);
byte[] outputKeyMaterial = new byte[32];

Hkdf<PlatformHmacSha256>.DeriveKey(sharedSecret, outputKeyMaterial, salt, "example v1 encryption"u8);

byte[] preMasterSecret = RandomNumberGenerator.GetBytes(48);
byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
byte[] serverRandom = RandomNumberGenerator.GetBytes(32);
byte[] masterSecret = new byte[48];

Tls12Prf<PlatformHmacSha256>.DeriveKey(preMasterSecret, "master secret"u8, clientRandom, serverRandom, masterSecret);
```

## BLAKE3 key derivation

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] outputKeyMaterial = new byte[32];

// A hardcoded, application-specific context string.
ReadOnlySpan<byte> context = "example.com 2020-01-01 session tokens v1"u8;

Blake3HashAlgorithm.DeriveKey(context, inputKeyMaterial, outputKeyMaterial);

// Incrementally.
using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.CreateDeriveKey(context);
hasher.Append(inputKeyMaterial);
hasher.GetCurrentHash(outputKeyMaterial);
```

## Argon2

`Argon2Parameters.Rfc9106FirstRecommended` (2 GiB, t = 1, p = 4) and `Rfc9106SecondRecommended` (64 MiB, t = 3, p = 4) are the settings that RFC 9106 recommends.

```csharp
using System.Security.Cryptography;
using System.Text;
using CryptoBase.Kdf;

byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[] key = new byte[32];

Argon2id.DeriveKey(password, salt, key, Argon2Parameters.Rfc9106SecondRecommended);

// On the calling thread only; the output is the same.
Argon2id.DeriveKey(password, salt, key, Argon2Parameters.Rfc9106SecondRecommended, maxDegreeOfParallelism: 1);

// Custom costs.
Argon2Parameters parameters = new(memorySizeInKibibytes: 19 * 1024, iterations: 2, parallelism: 1);
Argon2id.DeriveKey(password, salt, key, parameters);

// With a secret key (pepper) and associated data.
byte[] secret = RandomNumberGenerator.GetBytes(32);
Argon2id.DeriveKey(password, salt, key, parameters, secret, "user-id"u8);

// The other variants.
Argon2i.DeriveKey(password, salt, key, parameters);
Argon2d.DeriveKey(password, salt, key, parameters);
```

### Storing password hashes

`Argon2PasswordHasher` stores the variant, parameters, salt and hash in one PHC string, such as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.

```csharp
using System.Security.Cryptography;
using CryptoBase.Kdf;

Argon2Parameters current = new(memorySizeInKibibytes: 19 * 1024, iterations: 2, parallelism: 1);

// Registration: store the string.
string stored = Argon2PasswordHasher.Hash("correct horse battery staple"u8, current, Argon2Type.Argon2id);

// Login: verify, then rehash if current has been raised.
ReadOnlySpan<byte> attempt = "correct horse battery staple"u8;

if (Argon2PasswordHasher.Verify(attempt, stored))
{
    if (Argon2PasswordHasher.NeedsRehash(stored, current, Argon2Type.Argon2id))
    {
        stored = Argon2PasswordHasher.Hash(attempt, current, Argon2Type.Argon2id);
    }
}

// The string does not hold the pepper; pass it to both methods.
byte[] pepper = RandomNumberGenerator.GetBytes(32);
string peppered = Argon2PasswordHasher.Hash(attempt, current, Argon2Type.Argon2id, secret: pepper);
bool valid = Argon2PasswordHasher.Verify(attempt, peppered, pepper);
```

`Verify` and `NeedsRehash` throw `FormatException` for a malformed or unsupported string. `Verify` spends the time and memory that the string specifies, so verify only strings from trusted storage.
