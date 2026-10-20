# Key encapsulation

[Back to documentation](README.md)

CryptoBase implements ML-KEM from FIPS 203 in the `CryptoBase.Kems.MLKem` namespace:

| Type | Security category | Encapsulation key | Decapsulation key | Ciphertext | Shared secret | Private seed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `MLKem512` | 1 | 800 bytes | 1632 bytes | 768 bytes | 32 bytes | 64 bytes |
| `MLKem768` | 3 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes | 64 bytes |
| `MLKem1024` | 5 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes | 64 bytes |

Each type exposes these lengths as static properties, such as `MLKem768.CiphertextLength`. The examples use `MLKem768`.

## Generating a key pair

```csharp
using CryptoBase.Kems.MLKem;

using MLKem768 kem = MLKem768.GenerateKey();

// Send the encapsulation key to the peer.
byte[] encapsulationKey = new byte[MLKem768.EncapsulationKeyLength];
kem.ExportEncapsulationKey(encapsulationKey);
```

## Encapsulating to a peer

The peer imports the encapsulation key, creates a shared secret and sends the ciphertext back:

```csharp
using CryptoBase.Kems.MLKem;

using MLKem768 peer = MLKem768.ImportEncapsulationKey(encapsulationKey);

byte[] ciphertext = new byte[MLKem768.CiphertextLength];
Span<byte> sharedSecret = stackalloc byte[MLKem768.SharedSecretLength];
peer.Encapsulate(ciphertext, sharedSecret);
```

The two outputs must not overlap.

## Decapsulating

The holder of the key pair recovers the same shared secret from the ciphertext:

```csharp
Span<byte> sharedSecret = stackalloc byte[MLKem768.SharedSecretLength];
kem.Decapsulate(ciphertext, sharedSecret);
```

A ciphertext must have exactly `CiphertextLength` bytes; any other length throws `ArgumentException`. An instance imported from an encapsulation key alone throws `InvalidOperationException`.

Calls on one instance may run concurrently.

## Saving and restoring a key

The 64-byte private seed is the most compact form of a key pair:

```csharp
using CryptoBase.Kems.MLKem;

byte[] seed = new byte[MLKem768.PrivateSeedLength];
kem.ExportPrivateSeed(seed);

using MLKem768 restored = MLKem768.ImportPrivateSeed(seed);
```

`ExportDecapsulationKey` and `ImportDecapsulationKey` store the expanded decapsulation key instead. An instance imported from it has no seed, so `HasPrivateSeed` is `false` and `ExportPrivateSeed` throws `InvalidOperationException`. `HasDecapsulationKey` says whether an instance can decapsulate and export its decapsulation key.

Exports return the number of bytes written; a shorter destination throws `ArgumentException`. Disposing an instance erases its key material.

## Implicit rejection

`Decapsulate` never reports whether a ciphertext is genuine: an altered or foreign ciphertext yields a pseudorandom value instead of the shared secret, and the protocol has to detect the mismatch.

```csharp
ciphertext[0] ^= 1;

Span<byte> rejected = stackalloc byte[MLKem768.SharedSecretLength];
kem.Decapsulate(ciphertext, rejected);

// No exception: rejected differs from the peer's shared secret.
```

## Import checks

Imports apply the input checks of FIPS 203 and throw `ArgumentException` for a key that fails them:

- An encapsulation key must have exactly `EncapsulationKeyLength` bytes, and every coefficient it encodes must be below q = 3329.
- A decapsulation key must have exactly `DecapsulationKeyLength` bytes, the encapsulation key it embeds must pass the check above, and its hash of that key must match. Its secret coefficients must be below q too.
- A private seed must have exactly `PrivateSeedLength` bytes.

## Generic code

The three types implement `IKem<TSelf>`, so code can work with any of them:

```csharp
using CryptoBase.Abstractions.Kems;

static byte[] Encapsulate<T>(ReadOnlySpan<byte> encapsulationKey, Span<byte> sharedSecret) where T : class, IKem<T>
{
	using T kem = T.ImportEncapsulationKey(encapsulationKey);
	byte[] ciphertext = new byte[T.CiphertextLength];
	kem.Encapsulate(ciphertext, sharedSecret);
	return ciphertext;
}
```
