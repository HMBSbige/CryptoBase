# Digital signatures

[Back to documentation](README.md)

| Type | Namespace | Public key | Private key | Signature |
| --- | --- | ---: | ---: | ---: |
| `MLDsa44` | `CryptoBase.Signatures.MLDsa` | 1312 bytes | 2560 bytes | 2420 bytes |
| `MLDsa65` | `CryptoBase.Signatures.MLDsa` | 1952 bytes | 4032 bytes | 3309 bytes |
| `MLDsa87` | `CryptoBase.Signatures.MLDsa` | 2592 bytes | 4896 bytes | 4627 bytes |
| `EcdsaP256` | `CryptoBase.Signatures.Ecdsa` | 65 bytes | 32 bytes | at most 72 bytes |
| `EcdsaP384` | `CryptoBase.Signatures.Ecdsa` | 97 bytes | 48 bytes | at most 104 bytes |
| `EcdsaP521` | `CryptoBase.Signatures.Ecdsa` | 133 bytes | 66 bytes | at most 139 bytes |
| `Ed25519` | `CryptoBase.Signatures.EdDsa` | 32 bytes | 32 bytes | 64 bytes |
| `RsaKey` | `CryptoBase.Signatures.Rsa` | modulus of 512 to 16384 bits | two primes | as long as the modulus |

## ML-DSA

```csharp
using CryptoBase.Signatures.MLDsa;

using MLDsa65 signer = MLDsa65.GenerateKey();
byte[] publicKey = new byte[MLDsa65.PublicKeyLength];
signer.ExportPublicKey(publicKey);

byte[] message = "message"u8.ToArray();
byte[] signature = new byte[MLDsa65.SignatureLength];
signer.Sign(message, signature);

// One instance may sign and verify on several threads at once.
using MLDsa65 verifier = MLDsa65.ImportPublicKey(publicKey);
bool valid = verifier.Verify(message, signature); // true

// Optional context, up to MaxContextLength bytes; Verify needs the same one.
signer.Sign(message, signature, "example.com/v1"u8);
bool sameContext = verifier.Verify(message, signature, "example.com/v1"u8); // true

// HashML-DSA: the hash of the message and the OID of its algorithm (see the table below).
signer.SignPreHash(sha512Hash, signature, "2.16.840.1.101.3.4.2.3");
bool validPreHash = verifier.VerifyPreHash(sha512Hash, signature, "2.16.840.1.101.3.4.2.3"); // true

// External μ: mu has MLDsa65.MuLength bytes.
signer.SignMu(mu, signature);
bool validMu = verifier.VerifyMu(mu, signature); // true
```

Hash algorithms of `SignPreHash` and `VerifyPreHash`:

| Hash | OID | `MLDsa44` | `MLDsa65` | `MLDsa87` |
| --- | --- | :---: | :---: | :---: |
| SHA-256 | 2.16.840.1.101.3.4.2.1 | ✅ | | |
| SHA-384 | 2.16.840.1.101.3.4.2.2 | ✅ | ✅ | |
| SHA-512 | 2.16.840.1.101.3.4.2.3 | ✅ | ✅ | ✅ |
| SHA-512/256 | 2.16.840.1.101.3.4.2.6 | ✅ | | |
| SHA3-256 | 2.16.840.1.101.3.4.2.8 | ✅ | | |
| SHA3-384 | 2.16.840.1.101.3.4.2.9 | ✅ | ✅ | |
| SHA3-512 | 2.16.840.1.101.3.4.2.10 | ✅ | ✅ | ✅ |
| SHAKE128, 32 bytes of output | 2.16.840.1.101.3.4.2.11 | ✅ | | |
| SHAKE256, 64 bytes of output | 2.16.840.1.101.3.4.2.12 | ✅ | ✅ | ✅ |

### Keys

```csharp
using System.Security.Cryptography;

// Private seed, PrivateSeedLength bytes.
byte[] seed = new byte[MLDsa65.PrivateSeedLength];
key.ExportPrivateSeed(seed);
using MLDsa65 fromSeed = MLDsa65.ImportPrivateSeed(seed);

// Expanded private key; an instance imported from it has no seed, so its ExportPrivateSeed throws.
byte[] privateKey = new byte[MLDsa65.PrivateKeyLength];
key.ExportPrivateKey(privateKey);
using MLDsa65 fromPrivateKey = MLDsa65.ImportPrivateKey(privateKey);

// SubjectPublicKeyInfo and PKCS #8 (RFC 9881). The PKCS #8 export holds the seed if the instance has one,
// and the expanded key otherwise; the import accepts the seed, the expanded key or both.
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);
byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using MLDsa65 fromSpki = MLDsa65.ImportSubjectPublicKeyInfo(spki);
using MLDsa65 fromPkcs8 = MLDsa65.ImportPkcs8PrivateKey(pkcs8);

string publicPem = PemEncoding.WriteString("PUBLIC KEY", spki);
string privatePem = PemEncoding.WriteString("PRIVATE KEY", pkcs8);
```

## ECDSA

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;

using EcdsaP256 signer = EcdsaP256.GenerateKey();
byte[] publicKey = new byte[EcdsaP256.PublicKeyLength];
signer.ExportPublicKey(publicKey);

// The algorithm picks the hash: EcdsaSha256, EcdsaSha384 or EcdsaSha512. The signature is DER, and Sign returns its length.
byte[] message = "message"u8.ToArray();
byte[] buffer = new byte[signer.GetMaxSignatureLength(SignatureAlgorithm.EcdsaSha256)];
int written = signer.Sign(SignatureAlgorithm.EcdsaSha256, message, buffer);
byte[] signature = buffer.AsSpan(0, written).ToArray();

// Verify accepts only DER. One instance may sign and verify on several threads at once;
// to verify many signatures with one key, keep one instance, which gets faster after its first verification.
using EcdsaP256 verifier = EcdsaP256.ImportPublicKey(publicKey);
bool valid = verifier.Verify(SignatureAlgorithm.EcdsaSha256, message, signature); // true
```

### Keys

```csharp
// Private key: big-endian, PrivateKeyLength bytes. Public key: uncompressed, 0x04 ‖ x ‖ y.
byte[] privateKey = new byte[EcdsaP256.PrivateKeyLength];
key.ExportPrivateKey(privateKey);
using EcdsaP256 restored = EcdsaP256.ImportPrivateKey(privateKey);

// SubjectPublicKeyInfo and PKCS #8 with the curve named by OID; explicit curves and compressed points throw ArgumentException.
// The PKCS #8 import accepts a key without the curve or the public key, but throws if either does not match.
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);
byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using EcdsaP256 fromSpki = EcdsaP256.ImportSubjectPublicKeyInfo(spki);
using EcdsaP256 fromPkcs8 = EcdsaP256.ImportPkcs8PrivateKey(pkcs8);

// EC PRIVATE KEY: SignatureKey.ImportFromPem, below.
```

## Ed25519

```csharp
using CryptoBase.Signatures.EdDsa;
using System.Security.Cryptography;

using Ed25519 signer = Ed25519.GenerateKey();
byte[] publicKey = new byte[Ed25519.PublicKeyLength];
signer.ExportPublicKey(publicKey);

byte[] message = "message"u8.ToArray();
byte[] signature = new byte[Ed25519.SignatureLength];
signer.Sign(message, signature);

// ImportPublicKey throws ArgumentException for a key that is not the canonical encoding of a point.
// One instance may sign and verify on several threads at once; to verify many signatures with one key, keep one instance.
using Ed25519 verifier = Ed25519.ImportPublicKey(publicKey);
bool valid = verifier.Verify(message, signature); // true; false for a non-canonical signature

// Ed25519ctx: a context of 1 to MaxContextLength bytes. The empty default gives Ed25519.
signer.Sign(message, signature, "example.com/v1"u8);
bool sameContext = verifier.Verify(message, signature, "example.com/v1"u8); // true

// Ed25519ph: the SHA-512 hash of the message, with an optional context.
byte[] hash = SHA512.HashData(message);
signer.SignPreHash(hash, signature);
bool validPreHash = verifier.VerifyPreHash(hash, signature); // true
```

### Keys

```csharp
// Private key: the 32-byte secret of RFC 8032; any value is valid. Public key: 32 bytes.
byte[] privateKey = new byte[Ed25519.PrivateKeyLength];
key.ExportPrivateKey(privateKey);
using Ed25519 restored = Ed25519.ImportPrivateKey(privateKey);

// SubjectPublicKeyInfo and PKCS #8 (RFC 8410). The PKCS #8 export holds only the private key;
// the import also accepts a key with the public key, but throws if it does not match.
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);
byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using Ed25519 fromSpki = Ed25519.ImportSubjectPublicKeyInfo(spki);
using Ed25519 fromPkcs8 = Ed25519.ImportPkcs8PrivateKey(pkcs8);
```

## RSA

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Rsa;

// The modulus has a multiple of 8 bits from 2048 to 16384; the public exponent defaults to 65537.
using RsaKey signer = RsaKey.GenerateKey(3072);

// The algorithm picks the padding and the hash: RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512,
// RsaPssSha256, RsaPssSha384 or RsaPssSha512. RSASSA-PSS uses MGF1 with the same hash and a salt as long as the hash.
// A signature is as long as the modulus, the length that GetMaxSignatureLength gives.
byte[] message = "message"u8.ToArray();
byte[] signature = new byte[signer.GetMaxSignatureLength(SignatureAlgorithm.RsaPssSha256)];
signer.Sign(SignatureAlgorithm.RsaPssSha256, message, signature);

// One instance may sign and verify on several threads at once.
byte[] spki = new byte[signer.SubjectPublicKeyInfoLength];
signer.ExportSubjectPublicKeyInfo(spki);
using RsaKey verifier = RsaKey.ImportSubjectPublicKeyInfo(spki);
bool valid = verifier.Verify(SignatureAlgorithm.RsaPssSha256, message, signature); // true

// RSASSA-PKCS1-v1_5 verification also accepts a DigestInfo without the NULL parameters; Sign writes them.
// An algorithm that does not fit the modulus is not supported: RsaPssSha512 needs at least 1034 bits.
bool supported = verifier.Supports(SignatureAlgorithm.RsaPssSha512); // true for 3072 bits
```

### Keys

```csharp
using System.Security.Cryptography;

// The modulus has 512 to 16384 bits, and the public exponent at most 33 bits; other keys throw NotSupportedException.
int modulusBits = key.ModulusBits;

// PKCS #1 RSAPublicKey and RSAPrivateKey (RFC 8017), the contents of RSA PUBLIC KEY and RSA PRIVATE KEY blocks.
// The private key has two primes; a multi-prime key throws NotSupportedException.
byte[] rsaPublicKey = new byte[key.RsaPublicKeyLength];
key.ExportRsaPublicKey(rsaPublicKey);
byte[] rsaPrivateKey = new byte[key.RsaPrivateKeyLength];
key.ExportRsaPrivateKey(rsaPrivateKey);

using RsaKey fromRsaPublicKey = RsaKey.ImportRsaPublicKey(rsaPublicKey);
using RsaKey fromRsaPrivateKey = RsaKey.ImportRsaPrivateKey(rsaPrivateKey);
string rsaPrivatePem = PemEncoding.WriteString("RSA PRIVATE KEY", rsaPrivateKey);

// SubjectPublicKeyInfo and PKCS #8 with rsaEncryption and NULL parameters, or with id-RSASSA-PSS (below).
// The PKCS #8 import also accepts the public key beside the private key, but throws if it does not match.
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);
byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using RsaKey fromSpki = RsaKey.ImportSubjectPublicKeyInfo(spki);
using RsaKey fromPkcs8 = RsaKey.ImportPkcs8PrivateKey(pkcs8);
```

### RSASSA-PSS keys

```csharp
// A SubjectPublicKeyInfo or PKCS #8 key with id-RSASSA-PSS (RFC 4055) supports RSASSA-PSS alone:
// - without parameters: RsaPssSha256, RsaPssSha384 and RsaPssSha512;
// - with RSASSA-PSS-params: the algorithm of their hash, which must be SHA-256, SHA-384 or SHA-512, if MGF1 has the same hash
//   and their saltLength is at most the length of the hash. Parameters that allow none, such as SHA-1, throw NotSupportedException.
using RsaKey pssKey = RsaKey.ImportSubjectPublicKeyInfo(pssSpki);
bool pss = pssKey.Supports(SignatureAlgorithm.RsaPssSha256); // true if the parameters are absent or name SHA-256
bool pkcs1 = pssKey.Supports(SignatureAlgorithm.RsaPkcs1Sha256); // false

// ExportSubjectPublicKeyInfo and ExportPkcs8PrivateKey write the AlgorithmIdentifier of the import unchanged.
// RSAPublicKey and RSAPrivateKey hold no AlgorithmIdentifier: a key imported from them, or generated, has rsaEncryption.
```

## Keys of any algorithm

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using System.Security.Cryptography.X509Certificates;

// SignatureKey imports as the type that the encoding names: EcdsaP256, EcdsaP384, EcdsaP521, Ed25519, MLDsa44, MLDsa65, MLDsa87,
// or RsaKey for rsaEncryption and id-RSASSA-PSS. Another algorithm or curve throws NotSupportedException, as do RSA keys and
// RSASSA-PSS parameters that RsaKey does not support; a malformed encoding or an invalid key throws ArgumentException.
using ISignatureKey fromSpki = SignatureKey.ImportSubjectPublicKeyInfo(spki);
using ISignatureKey fromPkcs8 = SignatureKey.ImportPkcs8PrivateKey(pkcs8);

// The text must hold exactly one PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, RSA PRIVATE KEY or EC PRIVATE KEY block;
// other blocks, such as EC PARAMETERS, are ignored. EC PRIVATE KEY must name its curve. Encrypted keys are not supported.
using ISignatureKey key = SignatureKey.ImportFromPem(File.ReadAllText("key.pem"));

// An ML-DSA type and Ed25519 support only the algorithm of their name; an ECDSA type supports EcdsaSha256, EcdsaSha384 and EcdsaSha512;
// RsaKey supports the RSA algorithms that its modulus fits and its AlgorithmIdentifier allows.
SignatureAlgorithm algorithm = SignatureAlgorithm.EcdsaSha256;

if (key.HasPrivateKey && key.Supports(algorithm))
{
    byte[] buffer = new byte[key.GetMaxSignatureLength(algorithm)];
    int written = key.Sign(algorithm, "content"u8, buffer);
    bool valid = key.Verify(algorithm, "content"u8, buffer.AsSpan(0, written)); // true
}

// The ECDSA or RSA private key of an X509Certificate2, or false if the platform does not export it.
// On Windows and macOS, load a PKCS #12 file with X509KeyStorageFlags.Exportable.
using X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile("server.pfx", password, X509KeyStorageFlags.Exportable);

if (SignatureKey.TryImportPrivateKey(certificate, out ISignatureKey? certificateKey))
{
    using (certificateKey)
    {
        // Sign with certificateKey.
    }
}

// Generic code over a known type imports through ISignatureKey<TSelf>.
static bool Verify<T>(ReadOnlySpan<byte> spki, SignatureAlgorithm algorithm, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature) where T : class, ISignatureKey<T>
{
    using T key = T.ImportSubjectPublicKeyInfo(spki);
    return key.Supports(algorithm) && key.Verify(algorithm, content, signature);
}
```

For a certificate key that the platform does not export, see [Private keys of X509Certificate2](x509.md#private-keys-of-x509certificate2).
