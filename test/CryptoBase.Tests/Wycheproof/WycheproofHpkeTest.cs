using CryptoBase.Hpke;
using CryptoBase.Tests.Hpke;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Wycheproof;

// HPKE in base mode over DHKEM(X25519, HKDF-SHA256), through the public API. Where a vector has ikmE, the known-answer hooks also check the sender, which must give the enc and the ciphertexts of the vector.
public class WycheproofHpkeTest
{
	// A key of small order or of the wrong length is no encapsulation key. The acceptable vector has a key with bit 255 set, which the library takes and binds as given, as a sender that follows RFC 9180 to the letter does.
	[Test]
	[WycheproofVectors<HpkeTestGroup, HpkeTestVector>("hpke_x25519_encap_test.json")]
	public async Task Encapsulation(HpkeTestVector vector)
	{
		if (vector.Result is WycheproofResult.Invalid)
		{
			await Assert.That(() => DhKemX25519.ImportEncapsulationKey(vector.PkRm)).Throws<ArgumentException>().WithParameterName("source");
			return;
		}

		using (Assert.Multiple())
		{
			await Assert.That(vector.KemId).IsEqualTo(DhKemX25519.KemId);
			await Assert.That(vector.Result is WycheproofResult.Valid || vector.Flags is ["NonCanonicalPkRmLargeOrder"]).IsTrue();
			await AssertSeals(vector.PkRm, vector.Kdf, vector.Aead, Required(vector.IkmE), vector.Info, vector.Enc, [(vector.Aad, vector.Pt, vector.Ct)]);
		}
	}

	// An enc of small order or of the wrong length sets up no context; every other invalid vector sets one up that does not open the message. The acceptable vectors open: the library sets no limit on info, and takes an enc with bit 255 set or on the twist, as RFC 7748 does.
	[Test]
	[WycheproofVectors<HpkeTestGroup, HpkeTestVector>("hpke_x25519_decrypt_test.json")]
	public async Task Decryption(HpkeTestVector vector)
	{
		using DhKemX25519 recipient = DhKemX25519.ImportDecapsulationKey(Required(vector.SkRm));
		using HpkeRecipientContext? context = TryCreateRecipient(HpkeTestMode.Base, recipient, null, vector.Kdf, vector.Aead, vector.Enc, vector.Info, [], []);

		using (Assert.Multiple())
		{
			await Assert.That(vector.KemId).IsEqualTo(DhKemX25519.KemId);
			await Assert.That(vector.Result is not WycheproofResult.Acceptable || vector.Flags is ["LongInfo" or "NonCanonicalEncLargeOrder" or "Twist"]).IsTrue();
			await Assert.That(ExportEncapsulationKey(recipient)).IsEquivalentTo(vector.PkRm, CollectionOrdering.Matching);
			await Assert.That(context is null).IsEqualTo(vector.Flags is ["SmallOrderEnc" or "WrongLengthEnc" or "EncTrailingByteInContext"]);

			if (context is not null)
			{
				await AssertOpens(context, 0, vector.Aad, vector.Ct, vector.Result is WycheproofResult.Invalid ? null : vector.Pt);
			}

			if (vector.IkmE is not null)
			{
				await AssertSeals(vector.PkRm, vector.Kdf, vector.Aead, vector.IkmE, vector.Info, vector.Enc, [(vector.Aad, vector.Pt, vector.Ct)]);
			}
		}
	}

	// Each message is opened at the sequence number that the vector gives: a ciphertext that comes out of order or again fails, and the next one is then opened at the same number.
	[Test]
	[WycheproofVectors<HpkeSequenceTestGroup, HpkeSequenceTestVector>("hpke_x25519_sequence_test.json")]
	public async Task SequentialDecryption(HpkeSequenceTestVector vector)
	{
		using DhKemX25519 recipient = DhKemX25519.ImportDecapsulationKey(vector.SkRm);
		using HpkeRecipientContext? context = TryCreateRecipient(HpkeTestMode.Base, recipient, null, vector.Kdf, vector.Aead, vector.Enc, vector.Info, [], []);
		HpkeRecipientContext created = await Assert.That(context).IsNotNull();

		using (Assert.Multiple())
		{
			await Assert.That(vector.KemId).IsEqualTo(DhKemX25519.KemId);
			await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Valid);
			await Assert.That(ExportEncapsulationKey(recipient)).IsEquivalentTo(vector.PkRm, CollectionOrdering.Matching);

			foreach (HpkeDecryption decryption in vector.Decryptions)
			{
				await AssertOpens(created, decryption.SequenceNumber, decryption.Aad, decryption.Ct, decryption.Result is WycheproofResult.Valid ? decryption.Pt : null);
			}

			// The vectors with ikmE hold just the messages of their sender, in order.
			if (vector.IkmE is not null)
			{
				await Assert.That(vector.Decryptions).All(static decryption => decryption.Result is WycheproofResult.Valid);
				await AssertSeals(vector.PkRm, vector.Kdf, vector.Aead, vector.IkmE, vector.Info, vector.Enc, vector.Decryptions.Select(static decryption => (decryption.Aad, decryption.Pt, decryption.Ct)));
			}
		}
	}

	// The sender whose ephemeral key pair is DeriveKeyPair(ikmE) gives the enc of the vector and seals its messages, in order, into its ciphertexts.
	private static async Task AssertSeals(byte[] recipientPublicKey, HpkeKdfId kdf, HpkeAeadId aead, byte[] ikmE, byte[] info, byte[] expectedEnc, IEnumerable<(byte[] Aad, byte[] Pt, byte[] Ct)> messages)
	{
		using DhKemX25519 recipient = DhKemX25519.ImportEncapsulationKey(recipientPublicKey);
		(byte[] enc, byte[] sharedSecret) = Encapsulate(recipient, ikmE);
		using HpkeSenderContext sender = HpkeSenderContext.Create(DhKemX25519.KemId, HpkeMode.Base, kdf, aead, sharedSecret, info, [], []);

		await Assert.That(enc).IsEquivalentTo(expectedEnc, CollectionOrdering.Matching);

		foreach ((byte[] aad, byte[] pt, byte[] ct) in messages)
		{
			await Assert.That(Seal(sender, pt, aad)).IsEquivalentTo(ct, CollectionOrdering.Matching).Because($"sealing {sender.SequenceNumber - 1}");
		}
	}

	// Opens ciphertext at sequenceNumber into expected, which advances the sequence number, or, with expected null, fails to: the sequence number then stays, and the part of the buffer that would have received the message is cleared. Nothing is written past that part.
	private static async Task AssertOpens(HpkeRecipientContext context, ulong sequenceNumber, byte[] aad, byte[] ciphertext, byte[]? expected)
	{
		int length = Math.Max(0, ciphertext.Length - context.Aead.TagSize);
		byte[] plaintext = CreateGuardedBuffer(0, length);
		ulong sequenceNumberBefore = context.SequenceNumber;
		bool opened = context.TryOpen(ciphertext, plaintext, aad);
		string because = $"opening at {sequenceNumber}";

		await Assert.That(sequenceNumberBefore).IsEqualTo(sequenceNumber).Because(because);
		await Assert.That(opened).IsEqualTo(expected is not null).Because(because);
		await Assert.That(context.SequenceNumber).IsEqualTo(expected is null ? sequenceNumber : sequenceNumber + 1).Because(because);
		await Assert.That(plaintext.AsSpan(0, length).ToArray()).IsEquivalentTo(expected ?? new byte[length], CollectionOrdering.Matching).Because(because);
		await Assert.That(plaintext.AsSpan(length).ToArray()).All(static value => value is DestinationSentinel).Because(because);
	}

	private static byte[] Required(byte[]? value)
	{
		return value ?? throw new InvalidOperationException("The vector lacks a value the test needs.");
	}
}
