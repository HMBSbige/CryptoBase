# Key encapsulation

[Back to documentation](README.md)

| Type | Namespace | Encapsulation key | Decapsulation key | Ciphertext | Shared secret | Private seed |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `MLKem512` | `CryptoBase.Kems.MLKem` | 800 bytes | 1632 bytes | 768 bytes | 32 bytes | 64 bytes |
| `MLKem768` | `CryptoBase.Kems.MLKem` | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes | 64 bytes |
| `MLKem1024` | `CryptoBase.Kems.MLKem` | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes | 64 bytes |
| `SecP256r1MLKem768` | `CryptoBase.Kems.Hybrid` | 1249 bytes | 2432 bytes | 1153 bytes | 64 bytes | 96 bytes |
| `SecP384r1MLKem1024` | `CryptoBase.Kems.Hybrid` | 1665 bytes | 3216 bytes | 1665 bytes | 80 bytes | 112 bytes |

## ML-KEM

```csharp
using System.Security.Cryptography;
using CryptoBase.Kems.MLKem;

// Receiver.
using MLKem768 receiver = MLKem768.GenerateKey();
byte[] encapsulationKey = new byte[MLKem768.EncapsulationKeyLength];
receiver.ExportEncapsulationKey(encapsulationKey);

// Sender. ciphertext and sharedSecret must not overlap.
byte[] ciphertext = new byte[MLKem768.CiphertextLength];
byte[] senderSecret = new byte[MLKem768.SharedSecretLength];

using (MLKem768 sender = MLKem768.ImportEncapsulationKey(encapsulationKey))
{
    sender.Encapsulate(ciphertext, senderSecret);
}

// Receiver. One instance may encapsulate and decapsulate on several threads at once;
// an instance imported from an encapsulation key alone throws InvalidOperationException.
byte[] receiverSecret = new byte[MLKem768.SharedSecretLength];

if (!receiver.TryDecapsulate(ciphertext, receiverSecret))
{
    // The ciphertext has the wrong length; receiverSecret is unchanged.
    throw new CryptographicException("Invalid ciphertext.");
}

// receiverSecret equals senderSecret. For a changed ciphertext of the right length, TryDecapsulate returns true
// and writes a pseudorandom value instead.
```

### Keys

```csharp
// Private seed, PrivateSeedLength bytes.
byte[] seed = new byte[MLKem768.PrivateSeedLength];
key.ExportPrivateSeed(seed);
using MLKem768 fromSeed = MLKem768.ImportPrivateSeed(seed);

// Expanded decapsulation key; an instance imported from it has no seed.
byte[] decapsulationKey = new byte[MLKem768.DecapsulationKeyLength];
key.ExportDecapsulationKey(decapsulationKey);
using MLKem768 fromDecapsulationKey = MLKem768.ImportDecapsulationKey(decapsulationKey);

// What an instance holds; exporting anything else throws InvalidOperationException.
// Imports throw ArgumentException for the wrong length or a key that fails the checks of FIPS 203.
bool hasSeed = key.HasPrivateSeed; // GenerateKey, ImportPrivateSeed
bool hasDecapsulationKey = key.HasDecapsulationKey; // also ImportDecapsulationKey
```

## Hybrid KEMs

The encodings and shared secrets are those of the TLS groups SecP256r1MLKEM768 and SecP384r1MLKEM1024. Each value is its elliptic curve part followed by its ML-KEM part:

| Value | Elliptic curve part | ML-KEM part |
| --- | --- | --- |
| Encapsulation key | The public key, `0x04 ‖ x ‖ y` | The encapsulation key |
| Ciphertext | An ephemeral public key, `0x04 ‖ x ‖ y` | The ciphertext |
| Shared secret | The x-coordinate of the shared point, 32 or 48 big-endian bytes | The shared secret |
| Private seed | The private key, a big-endian integer | The private seed |
| Decapsulation key | The private key, a big-endian integer | The decapsulation key |

```csharp
using CryptoBase.Kems.Hybrid;

// Used like the ML-KEM types.
using SecP256r1MLKem768 receiver = SecP256r1MLKem768.GenerateKey();

// TryDecapsulate also returns false if the ephemeral public key is not an uncompressed point on the curve.
bool valid = receiver.TryDecapsulate(ciphertext, sharedSecret);

// The private seed and the decapsulation key are formats of this library; not every private seed of the right length is valid.
using SecP256r1MLKem768 fromSeed = SecP256r1MLKem768.ImportPrivateSeed(seed);
```

## Generic code

```csharp
using System.Security.Cryptography;
using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;

// The ML-KEM and hybrid types implement IKem<TSelf>.
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
