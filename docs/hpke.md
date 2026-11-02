# Hybrid public key encryption

[Back to documentation](README.md)

HPKE (RFC 9180) in the base, PSK, auth and auth_psk modes. The types are in `CryptoBase.Hpke`.

| KEM type | KEM ID | Encapsulation key | Decapsulation key | Encapsulated key | Shared secret | Private seed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `DhKemP256` | `0x0010` | 65 bytes | 32 bytes | 65 bytes | 32 bytes | 32 bytes |
| `DhKemP384` | `0x0011` | 97 bytes | 48 bytes | 97 bytes | 48 bytes | 48 bytes |
| `DhKemP521` | `0x0012` | 133 bytes | 66 bytes | 133 bytes | 64 bytes | 66 bytes |
| `DhKemX25519` | `0x0020` | 32 bytes | 32 bytes | 32 bytes | 32 bytes | 32 bytes |

| `HpkeKdf` | ID | `HashLength` |
| --- | ---: | ---: |
| `HkdfSha256` | `0x0001` | 32 bytes |
| `HkdfSha384` | `0x0002` | 48 bytes |
| `HkdfSha512` | `0x0003` | 64 bytes |

| `HpkeAead` | ID | `KeySize` | `NonceSize` | `TagSize` |
| --- | ---: | ---: | ---: | ---: |
| `Aes128Gcm` | `0x0001` | 16 bytes | 12 bytes | 16 bytes |
| `Aes256Gcm` | `0x0002` | 32 bytes | 12 bytes | 16 bytes |
| `ChaCha20Poly1305` | `0x0003` | 32 bytes | 12 bytes | 16 bytes |
| `ExportOnly` | `0xFFFF` | 0 | 0 | 0 |

## Encrypting to a public key

```csharp
using System.Security.Cryptography;
using CryptoBase.Hpke;

byte[] info = "application context"u8.ToArray();

// Recipient: a key pair, and its encapsulation key to publish.
using DhKemX25519 recipientKey = DhKemX25519.GenerateKey();
byte[] publicKey = new byte[DhKemX25519.EncapsulationKeyLength];
recipientKey.ExportEncapsulationKey(publicKey);

// Sender: set up a context, which writes the encapsulated key to send along.
using DhKemX25519 recipientPublicKey = DhKemX25519.ImportEncapsulationKey(publicKey);
byte[] enc = new byte[DhKemX25519.CiphertextLength];
using HpkeSenderContext sender = HpkeSenderContext.Create(recipientPublicKey, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info);

byte[] plaintext = "message"u8.ToArray();
byte[] associatedData = "header"u8.ToArray();
byte[] ciphertext = new byte[plaintext.Length + sender.Aead.TagSize];
sender.Seal(plaintext, ciphertext, associatedData);

// Recipient: set up the matching context from enc.
if (!HpkeRecipientContext.TryCreate(recipientKey, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info, out HpkeRecipientContext? recipient))
{
    // enc has the wrong length or is a point of small order.
    throw new CryptographicException("Invalid encapsulated key.");
}

using (recipient)
{
    byte[] decrypted = new byte[ciphertext.Length - recipient.Aead.TagSize];

    if (!recipient.TryOpen(ciphertext, decrypted, associatedData))
    {
        // Wrong key, info, associated data or order; the sequence number is unchanged.
        throw new AuthenticationTagMismatchException();
    }
}
```

Each `Seal` and `TryOpen` moves `SequenceNumber` on by one, so the messages open in the order they were sealed. A context is not thread-safe.

## Exporting secrets

```csharp
// Both sides derive the same secret; the length is at most 255 × Kdf.HashLength bytes.
byte[] senderSecret = new byte[32];
sender.Export("exporter context"u8, senderSecret);

byte[] recipientSecret = new byte[32];
recipient.Export("exporter context"u8, recipientSecret);

// A context that only exports: Seal and TryOpen throw InvalidOperationException.
using HpkeSenderContext exporter = HpkeSenderContext.Create(recipientPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ExportOnly, enc, info);
```

## Pre-shared keys and sender authentication

```csharp
// PSK mode: the PSK must be at least 32 bytes long and the PSK ID must not be empty.
using HpkeSenderContext pskSender = HpkeSenderContext.Create(recipientPublicKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, enc, info, psk, pskId);
bool created = HpkeRecipientContext.TryCreate(recipientKey, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, enc, info, psk, pskId, out HpkeRecipientContext? pskRecipient);

// Auth mode: the sender authenticates with its key pair; the recipient needs the sender's encapsulation key.
using DhKemX25519 senderKey = DhKemX25519.GenerateKey();
using HpkeSenderContext authSender = HpkeSenderContext.CreateAuthenticated(recipientPublicKey, senderKey, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info);

using DhKemX25519 senderPublicKey = DhKemX25519.ImportEncapsulationKey(senderEncapsulationKey);
bool authenticated = HpkeRecipientContext.TryCreateAuthenticated(recipientKey, senderPublicKey, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info, out HpkeRecipientContext? authRecipient);

// Auth_psk mode: CreateAuthenticated and TryCreateAuthenticated with psk and pskId.
```

## Setting up a recipient again

```csharp
// A context set up again from the same enc starts at sequence number 0; set SequenceNumber to continue
// where the previous context stopped.
if (HpkeRecipientContext.TryCreate(recipientKey, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info, out HpkeRecipientContext? again))
{
    using (again)
    {
        again.SequenceNumber = 1;
        bool opened = again.TryOpen(secondCiphertext, decrypted, secondAssociatedData);
    }
}
```

## Keys

```csharp
// Deterministic key pair from input keying material of any length. The instance has no private seed.
using DhKemX25519 derived = DhKemX25519.DeriveKeyPair(inputKeyMaterial);

// The private seed is PrivateSeedLength bytes of input keying material: GenerateKey draws one, and
// ImportPrivateSeed derives the same key pair as DeriveKeyPair and keeps the seed.
byte[] seed = new byte[DhKemX25519.PrivateSeedLength];
key.ExportPrivateSeed(seed);
using DhKemX25519 fromSeed = DhKemX25519.ImportPrivateSeed(seed);

// DhKemX25519: any 32 bytes are a decapsulation key, exported as imported; a clamped copy is the same key.
// The encapsulation key is the X25519 public key. ImportEncapsulationKey throws ArgumentException for the wrong
// length or a point of small order.
byte[] privateKey = new byte[DhKemX25519.DecapsulationKeyLength];
key.ExportDecapsulationKey(privateKey);
using DhKemX25519 fromPrivateKey = DhKemX25519.ImportDecapsulationKey(privateKey);

// DhKemP256, DhKemP384 and DhKemP521: the decapsulation key is the private key, big-endian, in [1, n − 1], and the
// encapsulation key is 0x04 ‖ x ‖ y. Imports throw ArgumentException for the wrong length, a private key out of range
// or a point not on the curve.
using DhKemP384 p384Key = DhKemP384.ImportDecapsulationKey(p384PrivateKey);
```

The DHKEM types implement `IKem<TSelf>`, so they also encapsulate and decapsulate as described in [Key encapsulation](key-encapsulation.md#generic-code), and `IHpkeAuthKem<TSelf>` adds `AuthEncapsulate` and `TryAuthDecapsulate`.

## Generic code

```csharp
using CryptoBase.Hpke;

// The setup methods take any IHpkeKem<TSelf>; the authenticated ones take an IHpkeAuthKem<TSelf>.
static (HpkeSenderContext Context, byte[] Enc) SetUpSender<TKem>(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> info) where TKem : class, IHpkeKem<TKem>
{
    using TKem recipient = TKem.ImportEncapsulationKey(publicKey);
    byte[] enc = new byte[TKem.CiphertextLength];
    return (HpkeSenderContext.Create(recipient, HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm, enc, info), enc);
}
```
