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

## Keys of any algorithm

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using System.Security.Cryptography.X509Certificates;

// SignatureKey imports as the type that the encoding names: EcdsaP256, EcdsaP384, EcdsaP521, MLDsa44, MLDsa65 or MLDsa87.
// Another algorithm or curve throws NotSupportedException; a malformed encoding or an invalid key throws ArgumentException.
using ISignatureKey fromSpki = SignatureKey.ImportSubjectPublicKeyInfo(spki);
using ISignatureKey fromPkcs8 = SignatureKey.ImportPkcs8PrivateKey(pkcs8);

// The text must hold exactly one PUBLIC KEY, PRIVATE KEY or EC PRIVATE KEY block; other blocks, such as EC PARAMETERS, are ignored.
// EC PRIVATE KEY must name its curve. Encrypted keys are not supported.
using ISignatureKey key = SignatureKey.ImportFromPem(File.ReadAllText("key.pem"));

// An ML-DSA type supports only the algorithm of its name; an ECDSA type supports EcdsaSha256, EcdsaSha384 and EcdsaSha512.
SignatureAlgorithm algorithm = SignatureAlgorithm.EcdsaSha256;

if (key.HasPrivateKey && key.Supports(algorithm))
{
    byte[] buffer = new byte[key.GetMaxSignatureLength(algorithm)];
    int written = key.Sign(algorithm, "content"u8, buffer);
    bool valid = key.Verify(algorithm, "content"u8, buffer.AsSpan(0, written)); // true
}

// The ECDSA private key of an X509Certificate2, or false if the platform does not export it.
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
