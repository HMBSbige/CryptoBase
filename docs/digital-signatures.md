# Digital signatures

[Back to documentation](README.md)

CryptoBase implements ML-DSA (FIPS 204) in the `CryptoBase.Signatures.MLDsa` namespace:

| Type | Security category | Public key | Private key | Signature | Private seed |
| --- | ---: | ---: | ---: | ---: | ---: |
| `MLDsa44` | 2 | 1312 bytes | 2560 bytes | 2420 bytes | 32 bytes |
| `MLDsa65` | 3 | 1952 bytes | 4032 bytes | 3309 bytes | 32 bytes |
| `MLDsa87` | 5 | 2592 bytes | 4896 bytes | 4627 bytes | 32 bytes |

## Signing and verifying

```csharp
using CryptoBase.Signatures.MLDsa;

// Signer: generate a key pair and give the public key to the verifiers.
using MLDsa65 signer = MLDsa65.GenerateKey();

byte[] publicKey = new byte[MLDsa65.PublicKeyLength];
signer.ExportPublicKey(publicKey);

// Signer: sign a message.
byte[] message = "message"u8.ToArray();
byte[] signature = new byte[MLDsa65.SignatureLength];
signer.Sign(message, signature);

// Verifier: import the public key and check the signature.
using MLDsa65 verifier = MLDsa65.ImportPublicKey(publicKey);

bool valid = verifier.Verify(message, signature); // true
bool tampered = verifier.Verify("massage"u8, signature); // false
```

Signing and verification may run concurrently on one instance.

### Context strings

`Sign` and `Verify` take an optional context string of up to `MaxContextLength` bytes:

```csharp
signer.Sign(message, signature, "example.com/v1"u8);

bool sameContext = verifier.Verify(message, signature, "example.com/v1"u8); // true
bool noContext = verifier.Verify(message, signature); // false
```

## Signing a hash (HashML-DSA)

`SignPreHash` and `VerifyPreHash` take the hash of the message and the dotted-decimal OID of the hash algorithm:

```csharp
using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.IO;
using CryptoBase.Signatures.MLDsa;

const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

using MLDsa65 signer = MLDsa65.GenerateKey();

// Hash the file with CryptoBase.IO.
byte[] hash = new byte[HashAlgorithm<Sha512Core>.HashLength];

using (FileStream file = File.OpenRead(path))
{
    HashAlgorithm<Sha512Core>.HashData(file, hash);
}

byte[] signature = new byte[MLDsa65.SignatureLength];
signer.SignPreHash(hash, signature, Sha512Oid);

bool valid = signer.VerifyPreHash(hash, signature, Sha512Oid); // true
```

Each type accepts these hash algorithms:

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

## Signing μ (external μ)

`SignMu` and `VerifyMu` take the message representative μ of FIPS 204, Algorithm 7, so only μ needs to reach the holder of the private key:

```csharp
// mu has MLDsa65.MuLength bytes.
byte[] signature = new byte[MLDsa65.SignatureLength];
signer.SignMu(mu, signature);

bool valid = signer.VerifyMu(mu, signature); // true
```

## Saving and restoring a key

The private seed is the most compact form of a key pair:

```csharp
using CryptoBase.Signatures.MLDsa;

using MLDsa65 key = MLDsa65.GenerateKey();

byte[] seed = new byte[MLDsa65.PrivateSeedLength];
key.ExportPrivateSeed(seed);

using MLDsa65 restored = MLDsa65.ImportPrivateSeed(seed);
```

The expanded private key of FIPS 204 is the other form. An instance imported from it holds no seed, so `ExportPrivateSeed` throws:

```csharp
byte[] privateKey = new byte[MLDsa65.PrivateKeyLength];
key.ExportPrivateKey(privateKey);

using MLDsa65 fromPrivateKey = MLDsa65.ImportPrivateKey(privateKey);
```

### DER encodings

SubjectPublicKeyInfo and PKCS #8 follow RFC 9881:

```csharp
using System.Security.Cryptography;

byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);

byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using MLDsa65 fromSpki = MLDsa65.ImportSubjectPublicKeyInfo(spki);
using MLDsa65 fromPkcs8 = MLDsa65.ImportPkcs8PrivateKey(pkcs8);

// PEM for files.
string publicPem = PemEncoding.WriteString("PUBLIC KEY", spki);
string privatePem = PemEncoding.WriteString("PRIVATE KEY", pkcs8);
```

`ImportPkcs8PrivateKey` accepts the seed, expandedKey and both forms. `ExportPkcs8PrivateKey` writes the seed form if the instance holds the seed, and the expandedKey form otherwise.

## Protocol code

The three types implement `ISignatureKey<TSelf>`, so protocol code such as TLS or X.509 can use a key without knowing its algorithm. Each type supports only the `SignatureAlgorithm` of the same name, which signs the whole message with an empty context.

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.MLDsa;

static byte[] Sign(ISignatureKey key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> content)
{
    byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
    int written = key.Sign(algorithm, content, signature);
    return signature.AsSpan(0, written).ToArray();
}

static bool Verify<T>(ReadOnlySpan<byte> subjectPublicKeyInfo, SignatureAlgorithm algorithm, ReadOnlySpan<byte> content, ReadOnlySpan<byte> signature) where T : class, ISignatureKey<T>
{
    using T key = T.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
    return key.Supports(algorithm) && key.Verify(algorithm, content, signature);
}

using MLDsa65 key = MLDsa65.GenerateKey();
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);

byte[] signature = Sign(key, SignatureAlgorithm.MLDsa65, "content"u8);
bool valid = Verify<MLDsa65>(spki, SignatureAlgorithm.MLDsa65, "content"u8, signature); // true
```
