# SM2

[Back to documentation](README.md)

SM2 (GB/T 32918-2016) over its recommended curve: digital signatures with SM3, public key encryption and the key exchange protocol, in `CryptoBase.SM2`, and ECDH over the same curve, `EcdhSM2` in `CryptoBase.KeyAgreements.Ecdh`.

| Type | Private key | Public key | Output |
| --- | ---: | ---: | --- |
| `SM2Key` | 32 bytes | 65 bytes | signatures of at most 72 bytes; ciphertexts 97 bytes longer than the plaintext, or up to `GetMaxDerCiphertextLength` as SM2Cipher |
| `SM2KeyExchange` | the `SM2Key` of the party | ephemeral key of 65 bytes | a key of any length and confirmations of 32 bytes |
| `EcdhSM2` | 32 bytes | 65 bytes | shared secret of 32 bytes |

## Signatures

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.SM2;

using SM2Key signer = SM2Key.GenerateKey();
byte[] publicKey = new byte[SM2Key.PublicKeyLength];
signer.ExportPublicKey(publicKey);

// The signature is DER, SEQUENCE { r INTEGER, s INTEGER }; Sign returns its length. Each signature of a message differs.
byte[] message = "message"u8.ToArray();
byte[] buffer = new byte[SM2Key.MaxSignatureLength];
int written = signer.Sign(message, buffer);
byte[] signature = buffer.AsSpan(0, written).ToArray();

// One instance may sign and verify on several threads at once; to verify many signatures with one key, keep one instance.
using SM2Key verifier = SM2Key.ImportPublicKey(publicKey);
bool valid = verifier.Verify(message, signature); // true

// The signer's ID goes into the signature, and the verifier needs the same one. Without one, Sign and Verify take
// SM2Key.DefaultId, the "1234567812345678" of GB/T 35276-2017; any ID of up to SM2Key.MaxIdLength bytes may take its place, the empty one included.
written = signer.Sign(message, buffer, "alice@example.com"u8);
bool sameId = verifier.Verify(message, buffer.AsSpan(0, written), "alice@example.com"u8); // true
bool otherId = verifier.Verify(message, buffer.AsSpan(0, written)); // false

// Through ISignatureKey, SignatureAlgorithm.SM2SM3 signs with the default ID.
ISignatureKey key = signer;
written = key.Sign(SignatureAlgorithm.SM2SM3, message, buffer);
```

For SM2 certificates, see [X.509 certificates](x509.md#sm2-certificates).

## Encryption

```csharp
using CryptoBase.SM2;

using SM2Key recipient = SM2Key.GenerateKey();
byte[] publicKey = new byte[SM2Key.PublicKeyLength];
recipient.ExportPublicKey(publicKey);

// A public key encrypts; to encrypt many messages with one key, keep one instance. The plaintext must not be empty.
using SM2Key sender = SM2Key.ImportPublicKey(publicKey);
byte[] plaintext = "secret"u8.ToArray();
byte[] ciphertext = new byte[SM2Key.GetCiphertextLength(plaintext.Length)];
sender.Encrypt(plaintext, ciphertext); // C1 ‖ C3 ‖ C2 of GB/T 32918.4-2016, C1 uncompressed; each encryption of a message differs

// The plaintext is 97 bytes shorter than the ciphertext.
byte[] decrypted = new byte[ciphertext.Length];

if (!recipient.TryDecrypt(ciphertext, decrypted, out int length))
{
    // Not a ciphertext of this key, or C1 not uncompressed: decrypted is unchanged.
}

// The SM2Cipher of GB/T 35276-2017, in DER; TryDecryptDer accepts no other encoding.
byte[] der = new byte[SM2Key.GetMaxDerCiphertextLength(plaintext.Length)];
int derLength = sender.EncryptDer(plaintext, der);
bool opened = recipient.TryDecryptDer(der.AsSpan(0, derLength), decrypted, out length); // true
```

## Key exchange

Two parties with static `SM2Key` key pairs and IDs agree on a key (GB/T 32918.3-2016). The initiator, user A of the standard, starts.

```csharp
using System.Security.Cryptography;
using CryptoBase.SM2;

// Each party has its own key pair and the static public key and ID of the other.
using SM2KeyExchange initiator = SM2KeyExchange.Create(aliceKey, aliceId, SM2KeyExchangeRole.Initiator);
byte[] ephemeralA = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
initiator.ExportEphemeralPublicKey(ephemeralA);
// Alice sends ephemeralA to Bob.

using SM2KeyExchange responder = SM2KeyExchange.Create(bobKey, bobId, SM2KeyExchangeRole.Responder);
byte[] ephemeralB = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
responder.ExportEphemeralPublicKey(ephemeralB);
byte[] bobSharedKey = new byte[16];
byte[] sB = new byte[SM2KeyExchange.ConfirmationLength];
byte[] expectedFromAlice = new byte[SM2KeyExchange.ConfirmationLength];

// alicePublic is an SM2Key with Alice's public key. false: ephemeralA is not a point on the curve.
if (!responder.TryDeriveKey(alicePublic, aliceId, ephemeralA, bobSharedKey, sB, expectedFromAlice))
{
    throw new CryptographicException("The key exchange failed.");
}

// Bob sends ephemeralB and sB to Alice.
byte[] aliceSharedKey = new byte[16];
byte[] sA = new byte[SM2KeyExchange.ConfirmationLength];
byte[] expectedFromBob = new byte[SM2KeyExchange.ConfirmationLength];

if (!initiator.TryDeriveKey(bobPublic, bobId, ephemeralB, aliceSharedKey, sA, expectedFromBob)
    || !CryptographicOperations.FixedTimeEquals(sB, expectedFromBob))
{
    throw new CryptographicException("The key exchange failed.");
}

// Alice sends sA to Bob, who checks it against expectedFromAlice in the same way.
// aliceSharedKey equals bobSharedKey.
```

The key may have any length but 0; both parties choose the same. The confirmations are optional: the overload of `TryDeriveKey` without them derives the key alone. An instance draws a new ephemeral key when it is created and derives once; create one per exchange.

## ECDH

`EcdhSM2` is ECDH over the SM2 curve, as TLS 1.3 uses it with curveSM2 (RFC 8998): the shared secret is the x-coordinate of the shared point. It works like the other ECDH types; see [Key agreement](key-agreement.md#ecdh).

```csharp
using CryptoBase.KeyAgreements.Ecdh;

using EcdhSM2 alice = EcdhSM2.GenerateKey();
using EcdhSM2 bob = EcdhSM2.GenerateKey();
byte[] bobPublicKey = new byte[EcdhSM2.PublicKeyLength];
bob.ExportPublicKey(bobPublicKey);

byte[] sharedSecret = new byte[EcdhSM2.SharedSecretLength];
bool derived = alice.TryDeriveSharedSecret(bobPublicKey, sharedSecret); // false if bobPublicKey is not on the curve
```

## Keys

```csharp
using CryptoBase.Abstractions.Signatures;
using CryptoBase.SM2;
using CryptoBase.Signatures;

using SM2Key key = SM2Key.GenerateKey();

// Private key: big-endian, 32 bytes, in [1, n − 2]. Public key: uncompressed, 0x04 ‖ x ‖ y. An invalid key throws ArgumentException.
byte[] privateKey = new byte[SM2Key.PrivateKeyLength];
key.ExportPrivateKey(privateKey);
using SM2Key restored = SM2Key.ImportPrivateKey(privateKey);

// SubjectPublicKeyInfo and PKCS #8 with id-ecPublicKey and the named curve 1.2.156.10197.1.301.
byte[] spki = new byte[key.SubjectPublicKeyInfoLength];
key.ExportSubjectPublicKeyInfo(spki);
byte[] pkcs8 = new byte[key.Pkcs8PrivateKeyLength];
key.ExportPkcs8PrivateKey(pkcs8);

using SM2Key fromSpki = SM2Key.ImportSubjectPublicKeyInfo(spki);
using SM2Key fromPkcs8 = SM2Key.ImportPkcs8PrivateKey(pkcs8);

// SignatureKey imports these encodings, and an EC PRIVATE KEY or SM2 PRIVATE KEY block that names the curve, as an SM2Key.
using ISignatureKey any = SignatureKey.ImportFromPem(File.ReadAllText("sm2.pem"));
```
