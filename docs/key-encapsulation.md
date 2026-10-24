# Key encapsulation

[Back to documentation](README.md)

CryptoBase implements ML-KEM (FIPS 203) in the `CryptoBase.Kems.MLKem` namespace:

| Type | Security category | Encapsulation key | Decapsulation key | Ciphertext | Shared secret | Private seed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `MLKem512` | 1 | 800 bytes | 1632 bytes | 768 bytes | 32 bytes | 64 bytes |
| `MLKem768` | 3 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes | 64 bytes |
| `MLKem1024` | 5 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes | 64 bytes |

The `CryptoBase.Kems.Hybrid` namespace combines ML-KEM with elliptic curve Diffie–Hellman; see [Hybrid KEMs](#hybrid-kems).

## Establishing a shared secret

```csharp
using System.Security.Cryptography;
using CryptoBase.Kems.MLKem;

// Receiver: generate a key pair and send the encapsulation key.
using MLKem768 receiver = MLKem768.GenerateKey();

byte[] encapsulationKey = new byte[MLKem768.EncapsulationKeyLength];
receiver.ExportEncapsulationKey(encapsulationKey);

// Sender: import the encapsulation key, create a shared secret and send the ciphertext.
byte[] ciphertext = new byte[MLKem768.CiphertextLength];
byte[] senderSecret = new byte[MLKem768.SharedSecretLength];

using (MLKem768 sender = MLKem768.ImportEncapsulationKey(encapsulationKey))
{
    sender.Encapsulate(ciphertext, senderSecret);
}

// Receiver: recover the shared secret from the ciphertext.
byte[] receiverSecret = new byte[MLKem768.SharedSecretLength];

if (!receiver.TryDecapsulate(ciphertext, receiverSecret))
{
    // The ciphertext is malformed; receiverSecret is unchanged.
    throw new CryptographicException("Invalid ciphertext.");
}

// senderSecret and receiverSecret are equal.
```

The shared secret can key an AEAD directly or feed [HKDF](macs-and-key-derivation.md#hkdf).

`TryDecapsulate` returns `false`, leaving `sharedSecret` unchanged, for a ciphertext of the wrong length or with an invalid public part, such as an elliptic curve point. `true` does not mean that the ciphertext was encapsulated to the key.

`TryDecapsulate` throws `ObjectDisposedException` after `Dispose`, `InvalidOperationException` on an instance imported from an encapsulation key alone, and `ArgumentException` if `sharedSecret` is too short. `Encapsulate` throws `ArgumentException` if `ciphertext` and `sharedSecret` overlap. Encapsulation and decapsulation may run concurrently on one instance.

ML-KEM checks only the length. For a changed or foreign ciphertext of the right length, it writes a pseudorandom value instead of the shared secret, so the receiver's AEAD decryption fails.

## Saving and restoring a key

The private seed is the most compact form of a key pair:

```csharp
using CryptoBase.Kems.MLKem;

using MLKem768 key = MLKem768.GenerateKey();

byte[] seed = new byte[MLKem768.PrivateSeedLength];
key.ExportPrivateSeed(seed);

using MLKem768 restored = MLKem768.ImportPrivateSeed(seed);
```

The expanded decapsulation key of FIPS 203 is the other form:

```csharp
byte[] decapsulationKey = new byte[MLKem768.DecapsulationKeyLength];
key.ExportDecapsulationKey(decapsulationKey);

using MLKem768 fromDecapsulationKey = MLKem768.ImportDecapsulationKey(decapsulationKey);
```

| Property | `GenerateKey`, `ImportPrivateSeed` | `ImportDecapsulationKey` | `ImportEncapsulationKey` |
| --- | :---: | :---: | :---: |
| `HasPrivateSeed` | ✅ | | |
| `HasDecapsulationKey` | ✅ | ✅ | |

Exporting what an instance does not hold throws `InvalidOperationException`. Imports throw `ArgumentException` for input of the wrong length or a key that fails the checks of FIPS 203.

## Hybrid KEMs

The `CryptoBase.Kems.Hybrid` namespace combines ECDH with ML-KEM. The encodings and shared secrets are those of the TLS groups SecP256r1MLKEM768 and SecP384r1MLKEM1024:

| Type | Curve | ML-KEM | Encapsulation key | Decapsulation key | Ciphertext | Shared secret | Private seed |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `SecP256r1MLKem768` | P-256 | ML-KEM-768 | 1249 bytes | 2432 bytes | 1153 bytes | 64 bytes | 96 bytes |
| `SecP384r1MLKem1024` | P-384 | ML-KEM-1024 | 1665 bytes | 3216 bytes | 1665 bytes | 80 bytes | 112 bytes |

Each value is its elliptic curve part followed by its ML-KEM part:

| Value | Elliptic curve part | ML-KEM part |
| --- | --- | --- |
| Encapsulation key | The public key, `0x04 ‖ x ‖ y` | The encapsulation key |
| Ciphertext | An ephemeral public key, `0x04 ‖ x ‖ y` | The ciphertext |
| Shared secret | The x-coordinate of the shared point, 32 or 48 big-endian bytes | The shared secret |
| Private seed | The private key, a big-endian integer | The private seed |
| Decapsulation key | The private key, a big-endian integer | The decapsulation key |

The private seed and the decapsulation key are formats of this library. Unlike an ML-KEM seed, not every private seed of the right length is valid.

They are used like the ML-KEM types. `TryDecapsulate` returns `false` for a ciphertext of the wrong length or whose ephemeral public key is not an uncompressed point on the curve.

The shared secret does not bind the ciphertext, so a protocol that needs that binding must include the ciphertext in its key derivation or transcript:

```csharp
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using CryptoBase.Kems.Hybrid;

using SecP256r1MLKem768 receiver = SecP256r1MLKem768.GenerateKey();

byte[] encapsulationKey = new byte[SecP256r1MLKem768.EncapsulationKeyLength];
receiver.ExportEncapsulationKey(encapsulationKey);

byte[] ciphertext = new byte[SecP256r1MLKem768.CiphertextLength];
byte[] sharedSecret = new byte[SecP256r1MLKem768.SharedSecretLength];

using (SecP256r1MLKem768 sender = SecP256r1MLKem768.ImportEncapsulationKey(encapsulationKey))
{
    sender.Encapsulate(ciphertext, sharedSecret);
}

// Derive the key from the secret, the encapsulation key and the ciphertext.
byte[] info = [.. "example v1 encryption"u8, .. encapsulationKey, .. ciphertext];
byte[] encryptionKey = new byte[32];
Hkdf.DeriveKey<Sha256Core>(sharedSecret, encryptionKey, [], info);
```

## Generic code

The ML-KEM and hybrid types implement `IKem<TSelf>`:

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;

static byte[] Encapsulate<T>(ReadOnlySpan<byte> encapsulationKey, Span<byte> sharedSecret) where T : class, IKem<T>
{
    using T kem = T.ImportEncapsulationKey(encapsulationKey);

    byte[] ciphertext = new byte[T.CiphertextLength];
    kem.Encapsulate(ciphertext, sharedSecret);
    return ciphertext;
}

static byte[] Decapsulate<T>(T kem, ReadOnlySpan<byte> ciphertext) where T : class, IKem<T>
{
    byte[] sharedSecret = new byte[T.SharedSecretLength];

    if (!kem.TryDecapsulate(ciphertext, sharedSecret))
    {
        throw new CryptographicException("Invalid ciphertext.");
    }

    return sharedSecret;
}

using MLKem1024 receiver = MLKem1024.GenerateKey();
byte[] encapsulationKey = new byte[MLKem1024.EncapsulationKeyLength];
receiver.ExportEncapsulationKey(encapsulationKey);

byte[] sharedSecret = new byte[MLKem1024.SharedSecretLength];
byte[] ciphertext = Encapsulate<MLKem1024>(encapsulationKey, sharedSecret);

byte[] receiverSecret = Decapsulate(receiver, ciphertext); // equal to sharedSecret
```
