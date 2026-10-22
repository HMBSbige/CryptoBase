# Key encapsulation

[Back to documentation](README.md)

CryptoBase implements ML-KEM (FIPS 203) in the `CryptoBase.Kems.MLKem` namespace:

| Type | Security category | Encapsulation key | Decapsulation key | Ciphertext | Shared secret | Private seed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `MLKem512` | 1 | 800 bytes | 1632 bytes | 768 bytes | 32 bytes | 64 bytes |
| `MLKem768` | 3 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes | 64 bytes |
| `MLKem1024` | 5 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes | 64 bytes |

## Establishing a shared secret

```csharp
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
receiver.Decapsulate(ciphertext, receiverSecret);

// senderSecret and receiverSecret are equal.
```

The shared secret can key an AEAD directly or feed [HKDF](macs-and-key-derivation.md#hkdf).

`Encapsulate` throws `ArgumentException` if `ciphertext` and `sharedSecret` overlap. `Decapsulate` throws `ArgumentException` for a ciphertext that does not have exactly `CiphertextLength` bytes, and `InvalidOperationException` on an instance imported from an encapsulation key alone. Encapsulation and decapsulation may run concurrently on one instance.

`Decapsulate` does not report a changed or foreign ciphertext of the right length: it writes a pseudorandom value instead of the shared secret, without throwing, so the receiver's AEAD decryption fails.

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

## Generic code

The three types implement `IKem<TSelf>`:

```csharp
using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;

static byte[] Encapsulate<T>(ReadOnlySpan<byte> encapsulationKey, Span<byte> sharedSecret) where T : class, IKem<T>
{
    using T kem = T.ImportEncapsulationKey(encapsulationKey);

    byte[] ciphertext = new byte[T.CiphertextLength];
    kem.Encapsulate(ciphertext, sharedSecret);
    return ciphertext;
}

using MLKem1024 receiver = MLKem1024.GenerateKey();
byte[] encapsulationKey = new byte[MLKem1024.EncapsulationKeyLength];
receiver.ExportEncapsulationKey(encapsulationKey);

byte[] sharedSecret = new byte[MLKem1024.SharedSecretLength];
byte[] ciphertext = Encapsulate<MLKem1024>(encapsulationKey, sharedSecret);
```
