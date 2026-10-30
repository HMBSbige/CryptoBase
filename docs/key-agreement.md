# Key agreement

[Back to documentation](README.md)

| Type | Namespace | Private key | Public key | Shared secret |
| --- | --- | ---: | ---: | ---: |
| `EcdhP256` | `CryptoBase.KeyAgreements.Ecdh` | 32 bytes | 65 bytes | 32 bytes |
| `EcdhP384` | `CryptoBase.KeyAgreements.Ecdh` | 48 bytes | 97 bytes | 48 bytes |
| `EcdhP521` | `CryptoBase.KeyAgreements.Ecdh` | 66 bytes | 133 bytes | 66 bytes |

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

## Generic code

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;

// The ECDH types implement IKeyAgreement<TSelf>.
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
