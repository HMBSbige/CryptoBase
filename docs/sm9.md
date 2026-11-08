# SM9

[Back to documentation](README.md)

SM9 (GB/T 38635.2-2020, GM/T 0044-2016) in `CryptoBase.SM9`: identity-based signatures, public key encryption, key encapsulation and key exchange. A key generation center (KGC) holds the master keys and extracts the private key of each user from the user's ID.

| Type | Holder | Private key | Public key |
| --- | --- | ---: | ---: |
| `SM9SignatureMasterKey` | the KGC; its public key verifies signatures | 32 bytes | 129 bytes |
| `SM9SignatureKey` | a user who signs | 65 bytes | the ID |
| `SM9EncryptionMasterKey` | the KGC; its public key encrypts and encapsulates | 32 bytes | 65 bytes |
| `SM9EncryptionKey` | a user who decrypts and decapsulates | 129 bytes | the ID |
| `SM9KeyExchangeKey` | a user of `SM9KeyExchange` | 129 bytes | the ID |

Signatures are 97 bytes, or 104 in DER; ciphertexts are 96 bytes longer than the plaintext; encapsulations are 65 bytes. The snippets below continue one another.

All of these types are `IDisposable`, and an operation on a disposed instance throws `ObjectDisposedException`. One instance of a key type may be used on several threads at once; `SM9KeyExchange` may not. For repeated operations, keep one instance rather than import the key each time.

## Key generation center

```csharp
using CryptoBase.SM9;

// Master private keys are 32 big-endian bytes, in [1, N − 1] for the group order N. Public keys and user private keys are uncompressed points,
// 0x04 ‖ x ‖ y, with each coordinate in Fp2 written as its u-coefficient and then its constant coefficient.
using SM9SignatureMasterKey signatureMaster = SM9SignatureMasterKey.GenerateKey();
using SM9EncryptionMasterKey encryptionMaster = SM9EncryptionMasterKey.GenerateKey();

byte[] signaturePublicKey = new byte[SM9SignatureMasterKey.PublicKeyLength];
signatureMaster.ExportPublicKey(signaturePublicKey);
byte[] encryptionPublicKey = new byte[SM9EncryptionMasterKey.PublicKeyLength];
encryptionMaster.ExportPublicKey(encryptionPublicKey);

// A master key round-trips through its private key. Invalid keys throw ArgumentException, as do the other imports.
byte[] masterPrivateKey = new byte[SM9SignatureMasterKey.PrivateKeyLength];
signatureMaster.ExportPrivateKey(masterPrivateKey);
using SM9SignatureMasterKey restoredMaster = SM9SignatureMasterKey.ImportPrivateKey(masterPrivateKey);

// An ID is any bytes. An ID with no key under the master key throws CryptographicException;
// GM/T 0044 has the KGC generate a new master key in that case.
byte[] aliceId = "alice@example.com"u8.ToArray();
byte[] bobId = "bob@example.com"u8.ToArray();
using SM9SignatureKey aliceSigner = signatureMaster.ExtractKey(aliceId);
using SM9EncryptionKey aliceDecryptor = encryptionMaster.ExtractKey(aliceId);
using SM9KeyExchangeKey aliceExchange = encryptionMaster.ExtractKeyExchangeKey(aliceId);
using SM9KeyExchangeKey bobExchange = encryptionMaster.ExtractKeyExchangeKey(bobId);

// A user imports its private key with the master public key and its ID; the import throws ArgumentException for a key of another ID or master key.
byte[] privateKey = new byte[SM9SignatureKey.PrivateKeyLength];
aliceSigner.ExportPrivateKey(privateKey);
using SM9SignatureKey imported = SM9SignatureKey.ImportPrivateKey(privateKey, signaturePublicKey, aliceId);
```

### Identifier hid

```csharp
using CryptoBase.SM9;

// The KGC chooses the identifier hid of each private key generating function, any byte, and publishes it with the master public key.
// The defaults are 0x01 for signatures and 0x03 for encryption and key encapsulation (GB/T 41389-2022), and 0x02 for the key exchange.
using SM9SignatureMasterKey hidSignatureMaster = SM9SignatureMasterKey.GenerateKey(hid: 0x05);
using SM9EncryptionMasterKey hidEncryptionMaster = SM9EncryptionMasterKey.GenerateKey(hid: 0x06);
byte[] hidSignaturePublicKey = new byte[SM9SignatureMasterKey.PublicKeyLength];
hidSignatureMaster.ExportPublicKey(hidSignaturePublicKey);
byte[] hidEncryptionPublicKey = new byte[SM9EncryptionMasterKey.PublicKeyLength];
hidEncryptionMaster.ExportPublicKey(hidEncryptionPublicKey);
using SM9SignatureKey hidSigner = hidSignatureMaster.ExtractKey(aliceId);

// The hid of the key exchange is chosen for each key; both parties need keys of the same hid.
using SM9KeyExchangeKey hidExchange = hidEncryptionMaster.ExtractKeyExchangeKey(aliceId, hid: 0x07);

// Verifiers, senders and users that import their private keys pass the same hid. With another one, signatures do not verify,
// ciphertexts do not decrypt, and the import throws ArgumentException.
using SM9SignatureMasterKey hidVerifier = SM9SignatureMasterKey.ImportPublicKey(hidSignaturePublicKey, hid: 0x05);
using SM9EncryptionMasterKey hidSender = SM9EncryptionMasterKey.ImportPublicKey(hidEncryptionPublicKey, hid: 0x06);
byte verifierHid = hidVerifier.Hid; // 0x05

byte[] hidPrivateKey = new byte[SM9SignatureKey.PrivateKeyLength];
hidSigner.ExportPrivateKey(hidPrivateKey);
using SM9SignatureKey hidImported = SM9SignatureKey.ImportPrivateKey(hidPrivateKey, hidSignaturePublicKey, aliceId, hid: 0x05);
```

## Signatures

```csharp
using CryptoBase.SM9;

// h ‖ S of GM/T 0044.2, or the SM9Signature of GB/T 41389-2022 (GM/T 0080-2020) in DER.
// Signing is randomized: signing a message twice gives two different signatures.
byte[] message = "message"u8.ToArray();
byte[] signature = new byte[SM9SignatureKey.SignatureLength];
aliceSigner.Sign(message, signature);
byte[] der = new byte[SM9SignatureKey.DerSignatureLength];
aliceSigner.SignDer(message, der);

// A verifier needs the master public key and the ID of the signer.
using SM9SignatureMasterKey verifier = SM9SignatureMasterKey.ImportPublicKey(signaturePublicKey);
bool valid = verifier.Verify(message, signature, aliceId); // true
bool validDer = verifier.VerifyDer(message, der, aliceId); // true
bool otherId = verifier.Verify(message, signature, "bob@example.com"u8); // false
```

## Encryption

```csharp
using CryptoBase.SM9;

// The sender needs the master public key and the ID of the recipient. The plaintext must not be empty.
using SM9EncryptionMasterKey sender = SM9EncryptionMasterKey.ImportPublicKey(encryptionPublicKey);
byte[] plaintext = "secret"u8.ToArray();
byte[] ciphertext = new byte[SM9EncryptionMasterKey.GetCiphertextLength(plaintext.Length)];

// C1 ‖ C3 ‖ C2 of GM/T 0044.4 with C1 as x ‖ y and the stream cipher of the KDF; the variant with a block cipher is not supported.
// Encryption is randomized.
sender.Encrypt(plaintext, ciphertext, aliceId);

// The plaintext is 96 bytes shorter than the ciphertext; a destination of that length or more will do.
byte[] decrypted = new byte[ciphertext.Length];

if (!aliceDecryptor.TryDecrypt(ciphertext, decrypted, out int length))
{
    // Not a ciphertext for this key: decrypted is unchanged.
}

// The SM9Cipher of GB/T 41389-2022 in DER, with EnType 0.
byte[] derCiphertext = new byte[SM9EncryptionMasterKey.GetDerCiphertextLength(plaintext.Length)];
sender.EncryptDer(plaintext, derCiphertext, aliceId);
bool opened = aliceDecryptor.TryDecryptDer(derCiphertext, decrypted, out length); // true
```

## Key encapsulation

```csharp
using CryptoBase.SM9;

// The sender gets a new random key and its encapsulation, a point in the uncompressed encoding, which it sends to the recipient.
// The key may have any length but 0.
byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
byte[] sharedKey = new byte[32];
sender.Encapsulate(encapsulation, sharedKey, aliceId);

// The recipient recovers the key; false for an encapsulation that is not a point of the curve.
// An encapsulation made for another ID or master key gives another key, not false.
byte[] recovered = new byte[32];
bool decapsulated = aliceDecryptor.TryDecapsulate(encapsulation, recovered);
```

## Key exchange

```csharp
using System.Security.Cryptography;
using CryptoBase.SM9;

// Two users with key exchange keys of one master key and one hid agree on a key (GM/T 0044.3). Each needs the ID of the other from the start.
// The initiator, user A of the standard, sends first. A key exchange key must outlive the instances that take it.
// An instance draws a new ephemeral key when it is created and derives once; create one per exchange. It is not thread-safe.
using SM9KeyExchange initiator = SM9KeyExchange.Create(aliceExchange, bobId, SM9KeyExchangeRole.Initiator);
byte[] ephemeralA = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
initiator.ExportEphemeralPublicKey(ephemeralA);
// Alice sends ephemeralA to Bob.

using SM9KeyExchange responder = SM9KeyExchange.Create(bobExchange, aliceId, SM9KeyExchangeRole.Responder);
byte[] ephemeralB = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
responder.ExportEphemeralPublicKey(ephemeralB);

// The key may have any length but 0; both parties choose the same.
byte[] bobSharedKey = new byte[16];
byte[] sB = new byte[SM9KeyExchange.ConfirmationLength];
byte[] expectedFromAlice = new byte[SM9KeyExchange.ConfirmationLength];

// false: ephemeralA is not a point of the curve.
if (!responder.TryDeriveKey(ephemeralA, bobSharedKey, sB, expectedFromAlice))
{
    throw new CryptographicException("The key exchange failed.");
}

// Bob sends ephemeralB and sB to Alice.
byte[] aliceSharedKey = new byte[16];
byte[] sA = new byte[SM9KeyExchange.ConfirmationLength];
byte[] expectedFromBob = new byte[SM9KeyExchange.ConfirmationLength];

if (!initiator.TryDeriveKey(ephemeralB, aliceSharedKey, sA, expectedFromBob)
    || !CryptographicOperations.FixedTimeEquals(sB, expectedFromBob))
{
    throw new CryptographicException("The key exchange failed.");
}

// Alice sends sA to Bob, who checks it against expectedFromAlice in the same way.
// aliceSharedKey equals bobSharedKey. The confirmations are optional: TryDeriveKey(peerEphemeralPublicKey, sharedKey) derives the key alone.
```
