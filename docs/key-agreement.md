# Key agreement

[Back to documentation](README.md)

| Type | Namespace | Private key | Public key | Shared secret |
| --- | --- | ---: | ---: | ---: |
| `EcdhP256` | `CryptoBase.KeyAgreements.Ecdh` | 32 bytes | 65 bytes | 32 bytes |
| `EcdhP384` | `CryptoBase.KeyAgreements.Ecdh` | 48 bytes | 97 bytes | 48 bytes |
| `EcdhP521` | `CryptoBase.KeyAgreements.Ecdh` | 66 bytes | 133 bytes | 66 bytes |
| `EcdhSM2` ([SM2](sm2.md#ecdh)) | `CryptoBase.KeyAgreements.Ecdh` | 32 bytes | 65 bytes | 32 bytes |
| `X25519` | `CryptoBase.KeyAgreements.Xdh` | 32 bytes | 32 bytes | 32 bytes |
| `X448` | `CryptoBase.KeyAgreements.Xdh` | 56 bytes | 56 bytes | 56 bytes |

## ECDH

```csharp
using System.Security.Cryptography;
using CryptoBase.KeyAgreements.Ecdh;

using EcdhP256 alice = EcdhP256.GenerateKey();
using EcdhP256 bob = EcdhP256.GenerateKey();

// Public key: uncompressed, 0x04 ‖ x ‖ y.
byte[] alicePublicKey = new byte[EcdhP256.PublicKeyLength];
byte[] bobPublicKey = new byte[EcdhP256.PublicKeyLength];
alice.ExportPublicKey(alicePublicKey);
bob.ExportPublicKey(bobPublicKey);

// The shared secret is the x-coordinate of the shared point. One instance may export and derive on several threads at once.
byte[] aliceSecret = new byte[EcdhP256.SharedSecretLength];

if (!alice.TryDeriveSharedSecret(bobPublicKey, aliceSecret))
{
    // The peer public key has the wrong length or is not an uncompressed point on the curve; aliceSecret is unchanged.
    throw new CryptographicException("Invalid public key.");
}

byte[] bobSecret = new byte[EcdhP256.SharedSecretLength];
bob.TryDeriveSharedSecret(alicePublicKey, bobSecret); // true; bobSecret equals aliceSecret
```

### Keys

```csharp
// Private key: big-endian, PrivateKeyLength bytes. Every instance holds one.
byte[] privateKey = new byte[EcdhP256.PrivateKeyLength];
key.ExportPrivateKey(privateKey);

// The wrong length or an invalid private key throws ArgumentException.
using EcdhP256 restored = EcdhP256.ImportPrivateKey(privateKey);
```

## X25519

```csharp
using System.Security.Cryptography;
using CryptoBase.KeyAgreements.Xdh;

using X25519 alice = X25519.GenerateKey();
using X25519 bob = X25519.GenerateKey();

// Public key: the u-coordinate, 32 little-endian bytes.
byte[] alicePublicKey = new byte[X25519.PublicKeyLength];
byte[] bobPublicKey = new byte[X25519.PublicKeyLength];
alice.ExportPublicKey(alicePublicKey);
bob.ExportPublicKey(bobPublicKey);

// One instance may export and derive on several threads at once.
byte[] aliceSecret = new byte[X25519.SharedSecretLength];

if (!alice.TryDeriveSharedSecret(bobPublicKey, aliceSecret))
{
    // The peer public key has the wrong length or a point of small order; aliceSecret is unchanged.
    // Any other 32 bytes are accepted.
    throw new CryptographicException("Invalid public key.");
}

byte[] bobSecret = new byte[X25519.SharedSecretLength];
bob.TryDeriveSharedSecret(alicePublicKey, bobSecret); // true; bobSecret equals aliceSecret
```

### Keys

```csharp
// Private key: any 32 bytes. It is clamped when used; ExportPrivateKey writes back the bytes that were imported.
byte[] privateKey = new byte[X25519.PrivateKeyLength];
key.ExportPrivateKey(privateKey);

// Only the wrong length throws ArgumentException.
using X25519 restored = X25519.ImportPrivateKey(privateKey);
```

## X448

```csharp
using System.Security.Cryptography;
using CryptoBase.KeyAgreements.Xdh;

using X448 alice = X448.GenerateKey();
using X448 bob = X448.GenerateKey();

// Public key: the u-coordinate, 56 little-endian bytes.
byte[] alicePublicKey = new byte[X448.PublicKeyLength];
byte[] bobPublicKey = new byte[X448.PublicKeyLength];
alice.ExportPublicKey(alicePublicKey);
bob.ExportPublicKey(bobPublicKey);

// One instance may export and derive on several threads at once.
byte[] aliceSecret = new byte[X448.SharedSecretLength];

if (!alice.TryDeriveSharedSecret(bobPublicKey, aliceSecret))
{
    // The peer public key has the wrong length or gives an all-zero shared secret, as a point of small order does; aliceSecret is unchanged.
    // Any other 56 bytes are accepted.
    throw new CryptographicException("Invalid public key.");
}

byte[] bobSecret = new byte[X448.SharedSecretLength];
bob.TryDeriveSharedSecret(alicePublicKey, bobSecret); // true; bobSecret equals aliceSecret
```

### Keys

```csharp
// Private key: any 56 bytes. It is clamped when used; ExportPrivateKey writes back the bytes that were imported.
byte[] privateKey = new byte[X448.PrivateKeyLength];
key.ExportPrivateKey(privateKey);

// Only the wrong length throws ArgumentException.
using X448 restored = X448.ImportPrivateKey(privateKey);
```

## Generic code

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;

// The ECDH types, X25519 and X448 implement IKeyAgreement<TSelf>.
static byte[] ExportPublicKey<T>(T key) where T : class, IKeyAgreement<T>
{
    byte[] publicKey = new byte[T.PublicKeyLength];
    key.ExportPublicKey(publicKey);
    return publicKey;
}

static byte[] DeriveSharedSecret<T>(T key, ReadOnlySpan<byte> peerPublicKey) where T : class, IKeyAgreement<T>
{
    byte[] sharedSecret = new byte[T.SharedSecretLength];

    if (!key.TryDeriveSharedSecret(peerPublicKey, sharedSecret))
    {
        throw new CryptographicException("Invalid public key.");
    }

    return sharedSecret;
}

using EcdhP256 alice = EcdhP256.GenerateKey();
using EcdhP256 bob = EcdhP256.GenerateKey();

byte[] aliceSecret = DeriveSharedSecret(alice, ExportPublicKey(bob));
byte[] bobSecret = DeriveSharedSecret(bob, ExportPublicKey(alice)); // equal to aliceSecret
```
