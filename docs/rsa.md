# RSA

[Back to documentation](README.md)

RSA (RFC 8017) in `CryptoBase.Rsa`: `RsaKey` signs with RSASSA-PKCS1-v1_5 and RSASSA-PSS, and encrypts with RSAES-OAEP. RSAES-PKCS1-v1_5 encryption is not supported.

| Type | Private key | Public key | Output |
| --- | --- | --- | --- |
| `RsaKey` | two primes | modulus of 512 to 16384 bits | signatures and ciphertexts as long as the modulus |

## Signatures

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Rsa;

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

## Encryption

```csharp
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Rsa;

using RsaKey recipient = RsaKey.GenerateKey(3072);
byte[] spki = new byte[recipient.SubjectPublicKeyInfoLength];
recipient.ExportSubjectPublicKeyInfo(spki);

// The type argument is the hash of the label and of MGF1, of 1 to 64 bytes, such as Sha1Core, Sha256Core or Sha512Core.
// A plaintext has at most k − 2·hLen − 2 bytes, where k is ModulusLength: 318 for 3072 bits with SHA-256.
// A modulus too short for the hash, or a key with id-RSASSA-PSS, throws NotSupportedException.
using RsaKey sender = RsaKey.ImportSubjectPublicKeyInfo(spki);
byte[] plaintext = "secret"u8.ToArray();
byte[] label = "context"u8.ToArray(); // optional; decryption needs the same one
byte[] ciphertext = new byte[sender.ModulusLength];
sender.EncryptOaep<Sha256Core>(plaintext, ciphertext, label); // each encryption of a plaintext differs

// The destination must hold the longest plaintext, whatever the ciphertext holds.
byte[] buffer = new byte[recipient.GetMaxOaepPlaintextLength<Sha256Core>()];

if (recipient.TryDecryptOaep<Sha256Core>(ciphertext, buffer, out int written, label))
{
    byte[] decrypted = buffer.AsSpan(0, written).ToArray();
}
else
{
    // Not a ciphertext of this key, hash and label: buffer is unchanged.
}

// MGF1 with another hash than that of the label.
sender.EncryptOaep<Sha256Core, Sha1Core>(plaintext, ciphertext);
bool decrypts = recipient.TryDecryptOaep<Sha256Core, Sha1Core>(ciphertext, buffer, out written); // true

// One instance may encrypt, decrypt, sign and verify on several threads at once.
// Decryption throws CryptographicException rather than return a result that the public key does not map back to the ciphertext, as signing does.
```

## Keys

```csharp
using System.Security.Cryptography;
using CryptoBase.Rsa;

using RsaKey key = RsaKey.GenerateKey(3072);

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

## RSASSA-PSS keys

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
