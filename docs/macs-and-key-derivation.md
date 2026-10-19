# MACs and key derivation

[Back to documentation](README.md)

## HMAC

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Macs.Hmac;

byte[] key = RandomNumberGenerator.GetBytes(32);
Span<byte> tag = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

// Authenticate the complete input.
HmacAlgorithm<Sha256HashAlgorithm>.Mac(key, "message"u8, tag);

// Create an incremental HMAC instance.
using HmacAlgorithm<Sha256HashAlgorithm> mac = HmacAlgorithm<Sha256HashAlgorithm>.Create(key);

// Append input.
mac.Append("message"u8);

// Get the current MAC without resetting.
mac.GetCurrentMac(tag);

// Get the current MAC and reset while retaining the key.
mac.GetMacAndReset(tag);

// Discard the current input while retaining the key.
mac.Append("discarded"u8);
mac.Reset();
```

## Platform-backed HMAC-SHA256

`PlatformHmacSha256` computes HMAC-SHA256 with the operating system's cryptographic library. It implements `IMacAlgorithm<TSelf>`, so it can replace `HmacAlgorithm<Sha256HashAlgorithm>` in generic code, `MacStream<T>` and the generic KDFs below. `IsPreferred` is `true` on x86 and x64 processors with the SHA extensions, where it is expected to be faster than the managed implementation.

```csharp
using System.Security.Cryptography;
using CryptoBase.Platform;

byte[] key = RandomNumberGenerator.GetBytes(32);
Span<byte> tag = stackalloc byte[PlatformHmacSha256.MacLength];

// Authenticate the complete input.
PlatformHmacSha256.Mac(key, "message"u8, tag);
```

## Poly1305

```csharp
using System.Security.Cryptography;
using CryptoBase.Macs.Poly1305;

// Generate a new one-time key for each message.
byte[] key = RandomNumberGenerator.GetBytes(Poly1305Algorithm.KeyLengthInBytes);
Span<byte> tag = stackalloc byte[Poly1305Algorithm.MacLength];

// Authenticate the complete input.
Poly1305Algorithm.Mac(key, "message"u8, tag);
```

## BLAKE3 keyed hash

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

byte[] key = RandomNumberGenerator.GetBytes(Blake3HashAlgorithm.KeyLengthInBytes);
Span<byte> tag = stackalloc byte[Blake3HashAlgorithm.HashLength];

// Authenticate the complete input.
Blake3HashAlgorithm.KeyedHashData(key, "message"u8, tag);

// Create an incremental keyed hasher.
using Blake3HashAlgorithm mac = Blake3HashAlgorithm.CreateKeyed(key);
mac.Append("message"u8);

// Get the current tag and reset while retaining the key.
mac.GetHashAndReset(tag);
```

## HKDF

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);
ReadOnlySpan<byte> info = "example encryption key"u8;
byte[] outputKeyMaterial = new byte[32];

// Extract and expand in one call.
Hkdf.DeriveKey<Sha256HashAlgorithm>(inputKeyMaterial, outputKeyMaterial, salt, info);

Span<byte> pseudorandomKey = stackalloc byte[HmacAlgorithm<Sha256HashAlgorithm>.MacLength];

// Extract a pseudorandom key.
Hkdf.Extract<Sha256HashAlgorithm>(inputKeyMaterial, salt, pseudorandomKey);

// Expand the pseudorandom key.
Hkdf.Expand<Sha256HashAlgorithm>(pseudorandomKey, outputKeyMaterial, info);
```

## TLS 1.2 PRF

The cipher suite selects the hash; the cipher suites defined in RFC 5246 use SHA-256. The overload with two seed parts takes `seed1 || seed2` without concatenating them.

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Kdf;

byte[] preMasterSecret = RandomNumberGenerator.GetBytes(48);
byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
byte[] serverRandom = RandomNumberGenerator.GetBytes(32);
byte[] masterSecret = new byte[48];
byte[] keyBlock = new byte[128];

// The master secret uses the seed client_random || server_random.
Tls12Prf.DeriveKey<Sha256HashAlgorithm>(preMasterSecret, "master secret"u8, clientRandom, serverRandom, masterSecret);

// The key block reverses the order to server_random || client_random.
Tls12Prf.DeriveKey<Sha256HashAlgorithm>(masterSecret, "key expansion"u8, serverRandom, clientRandom, keyBlock);

// The extended master secret from RFC 7627 uses the session hash as the seed.
byte[] sessionHash = SHA256.HashData("handshake messages"u8);
Tls12Prf.DeriveKey<Sha256HashAlgorithm>(preMasterSecret, "extended master secret"u8, sessionHash, masterSecret);
```

## HKDF and TLS 1.2 PRF over a chosen HMAC implementation

`Hkdf<TMac>` and `Tls12Prf<TMac>` provide the same methods as the classes above, with the HMAC implementation that the type argument selects. The type argument must be an HMAC: RFC 5869 and RFC 5246 define these functions over HMAC only, and their security does not carry over to other MACs.

```csharp
using System.Security.Cryptography;
using CryptoBase.Kdf;
using CryptoBase.Platform;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] salt = RandomNumberGenerator.GetBytes(32);
byte[] outputKeyMaterial = new byte[32];

// HKDF over the platform HMAC.
Hkdf<PlatformHmacSha256>.DeriveKey(inputKeyMaterial, outputKeyMaterial, salt, "example encryption key"u8);

byte[] preMasterSecret = RandomNumberGenerator.GetBytes(48);
byte[] clientRandom = RandomNumberGenerator.GetBytes(32);
byte[] serverRandom = RandomNumberGenerator.GetBytes(32);
byte[] masterSecret = new byte[48];

// The TLS 1.2 PRF over the platform HMAC.
Tls12Prf<PlatformHmacSha256>.DeriveKey(preMasterSecret, "master secret"u8, clientRandom, serverRandom, masterSecret);
```

## BLAKE3 key derivation

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Blake3;

byte[] inputKeyMaterial = RandomNumberGenerator.GetBytes(32);
byte[] outputKeyMaterial = new byte[32];

// The context string should be hardcoded, globally unique and application-specific.
ReadOnlySpan<byte> context = "example.com 2020-01-01 session tokens v1"u8;

Blake3HashAlgorithm.DeriveKey(context, inputKeyMaterial, outputKeyMaterial);

// Derive incrementally.
using Blake3HashAlgorithm hasher = Blake3HashAlgorithm.CreateDeriveKey(context);
hasher.Append(inputKeyMaterial);
hasher.GetCurrentHash(outputKeyMaterial);
```

## Argon2

Argon2id, Argon2i and Argon2d take the same arguments. RFC 9106 makes Argon2id the primary variant. Argon2d's memory accesses depend on the password, so use it only where side-channel attacks are not a threat.

```csharp
using System.Security.Cryptography;
using System.Text;
using CryptoBase.Kdf;

byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[] tag = new byte[32];

// Use RFC 9106's second recommended option: m = 64 MiB, t = 3, p = 4.
Argon2id.DeriveKey(password, salt, tag, Argon2Parameters.Rfc9106SecondRecommended);

// Fill the four lanes on the calling thread only. The tag is the same.
Argon2id.DeriveKey(password, salt, tag, Argon2Parameters.Rfc9106SecondRecommended, maxDegreeOfParallelism: 1);

// Choose custom costs, here OWASP's recommended minimum for Argon2id.
Argon2Parameters parameters = new(memorySizeInKibibytes: 19 * 1024, iterations: 2, parallelism: 1);
Argon2id.DeriveKey(password, salt, tag, parameters);

// Add a secret key (pepper) and associated data.
byte[] secret = RandomNumberGenerator.GetBytes(32);
Argon2id.DeriveKey(password, salt, tag, parameters, secret, "user-id"u8);

// Use the other types.
Argon2i.DeriveKey(password, salt, tag, parameters);
Argon2d.DeriveKey(password, salt, tag, parameters);
```

`Argon2PasswordHasher` stores a password hash with its type, parameters and salt in the PHC string format of the Argon2 reference implementation, such as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. `Verify` and `NeedsRehash` throw `FormatException` for a malformed or unsupported string. `Verify` costs the time and memory the string specifies, so verify only strings from trusted storage.

```csharp
using System.Security.Cryptography;
using CryptoBase.Kdf;

ReadOnlySpan<byte> password = "correct horse battery staple"u8;
Argon2Parameters parameters = new(memorySizeInKibibytes: 19 * 1024, iterations: 2, parallelism: 1);

// Hash with a random 16-byte salt into a 32-byte hash.
string stored = Argon2PasswordHasher.Hash(password, parameters, Argon2Type.Argon2id);

// Verify a password against the stored string.
bool valid = Argon2PasswordHasher.Verify(password, stored);

// Once a password is verified, hash it again if the stored settings are not the current ones.
if (valid && Argon2PasswordHasher.NeedsRehash(stored, Argon2Parameters.Rfc9106SecondRecommended, Argon2Type.Argon2id))
{
    stored = Argon2PasswordHasher.Hash(password, Argon2Parameters.Rfc9106SecondRecommended, Argon2Type.Argon2id);
}

// The string does not hold the secret key (pepper), so pass it to both methods.
byte[] secret = RandomNumberGenerator.GetBytes(32);
string peppered = Argon2PasswordHasher.Hash(password, parameters, Argon2Type.Argon2id, secret: secret);
valid = Argon2PasswordHasher.Verify(password, peppered, secret);
```
