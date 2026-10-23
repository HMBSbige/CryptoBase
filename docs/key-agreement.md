# Key agreement

[Back to documentation](README.md)

CryptoBase implements elliptic curve Diffie–Hellman (ECDH) in the `CryptoBase.KeyAgreements.Ecdh` namespace:

| Type | Curve | Private key | Public key | Shared secret |
| --- | --- | ---: | ---: | ---: |
| `EcdhP256` | P-256 (secp256r1) | 32 bytes | 65 bytes | 32 bytes |
| `EcdhP384` | P-384 (secp384r1) | 48 bytes | 97 bytes | 48 bytes |
| `EcdhP521` | P-521 (secp521r1) | 66 bytes | 133 bytes | 66 bytes |

The private key is a big-endian integer, the public key the uncompressed point `0x04 ‖ x ‖ y`, and the shared secret the x-coordinate of the shared point.

## Agreeing on a key

```csharp
using System.Security.Cryptography;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using CryptoBase.KeyAgreements.Ecdh;

// Each party generates a key pair and sends its public key.
using EcdhP256 alice = EcdhP256.GenerateKey();
using EcdhP256 bob = EcdhP256.GenerateKey();

byte[] alicePublicKey = new byte[EcdhP256.PublicKeyLength];
byte[] bobPublicKey = new byte[EcdhP256.PublicKeyLength];
alice.ExportPublicKey(alicePublicKey);
bob.ExportPublicKey(bobPublicKey);

// Each party derives the shared secret from the other's public key.
byte[] aliceSecret = new byte[EcdhP256.SharedSecretLength];

if (!alice.TryDeriveSharedSecret(bobPublicKey, aliceSecret))
{
    // The public key is invalid; aliceSecret is unchanged.
    throw new CryptographicException("Invalid public key.");
}

byte[] bobSecret = new byte[EcdhP256.SharedSecretLength];

if (!bob.TryDeriveSharedSecret(alicePublicKey, bobSecret))
{
    throw new CryptographicException("Invalid public key.");
}

// aliceSecret and bobSecret are equal. Derive the key from the secret and both public keys, in an order both sides agree on.
byte[] info = [.. "example v1 encryption"u8, .. alicePublicKey, .. bobPublicKey];
byte[] encryptionKey = new byte[32];
Hkdf.DeriveKey<Sha256Core>(aliceSecret, encryptionKey, [], info);
```

See [HKDF](macs-and-key-derivation.md#hkdf) for the salt and for deriving several keys from one secret.

`TryDeriveSharedSecret` returns `false`, leaving `sharedSecret` unchanged, for a peer public key of the wrong length or one that is not an uncompressed point on the curve. It throws `ObjectDisposedException` after `Dispose` and `ArgumentException` if `sharedSecret` is too short. The peer public key may overlap `sharedSecret`. Exports and derivations may run concurrently on one instance.

## Saving and restoring a key

```csharp
using CryptoBase.KeyAgreements.Ecdh;

using EcdhP256 key = EcdhP256.GenerateKey();

byte[] privateKey = new byte[EcdhP256.PrivateKeyLength];
key.ExportPrivateKey(privateKey);

using EcdhP256 restored = EcdhP256.ImportPrivateKey(privateKey);
```

`ImportPrivateKey` throws `ArgumentException` for input of the wrong length or an invalid private key. Every instance holds a private key; peer public keys are passed to `TryDeriveSharedSecret` as bytes.

## Generic code

The ECDH types implement `IKeyAgreement<TSelf>`:

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;

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
