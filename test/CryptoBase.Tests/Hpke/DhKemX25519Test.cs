using CryptoBase.Hpke;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.KeyAgreements.Xdh.X25519TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hpke;

// What DHKEM(X25519) adds to DhKemTest: DeriveKeyPair without rejection sampling, decapsulation keys kept unclamped, and public keys taken in any encoding except those of small order. Expected values come from the platform's HKDF and the reference ladder.
public class DhKemX25519Test
{
	private static readonly byte[] SuiteId = [.. "KEM"u8, 0x00, 0x20];
	private static readonly byte[] Nine = EncodeInteger(9);

	// RFC 9180, Section 7.1.3: sk = LabeledExpand(LabeledExtract("", "dkp_prk", ikm), "sk", "", 32), for any length of ikm; the seed is written back as given.
	[Test]
	public async Task DeriveKeyPairExpandsAnyInputIntoTheKey()
	{
		byte[][] inputs = [[], [0x00], CreateDeterministicSource(31), new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray(), CreateDeterministicSource(33), CreateDeterministicSource(66), CreateDeterministicSource(1000)];

		using (Assert.Multiple())
		{
			foreach (byte[] ikm in inputs)
			{
				byte[] privateKey = HKDF.Expand(HashAlgorithmName.SHA256, LabeledExtract("dkp_prk"u8, ikm), 32, LabeledInfo("sk"u8, [], 32));
				using DhKemX25519 derived = DhKemX25519.DeriveKeyPair(ikm);

				await Assert.That(ExportDecapsulationKey(derived)).IsEquivalentTo(privateKey, CollectionOrdering.Matching).Because($"ikm of {ikm.Length} bytes");
				await Assert.That(ExportEncapsulationKey(derived)).IsEquivalentTo(X25519Function(privateKey, Nine), CollectionOrdering.Matching).Because($"ikm of {ikm.Length} bytes");

				if (ikm.Length == DhKemX25519.PrivateSeedLength)
				{
					using DhKemX25519 fromSeed = DhKemX25519.ImportPrivateSeed(ikm);
					await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(ikm, CollectionOrdering.Matching);
					await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				}
			}
		}
	}

	// A key exports as imported, and its clamped form, which erratum 7121 to RFC 9180 gives for the vectors, is the same key: the same encapsulation key, and the vector's shared secret on both sides.
	[Test]
	public async Task DecapsulationKeysExportAsImportedAndClampingKeepsThem()
	{
		HpkeVector[] vectors = [.. HpkeVectors.Full().Where(static vector => vector.KemId is 0x0020)];
		HpkeVector first = vectors.First(static vector => vector is { Source: "RFC 9180", Mode: 0, Kdf: HpkeKdf.HkdfSha256, Aead: HpkeAead.Aes128Gcm });

		using (Assert.Multiple())
		{
			await Assert.That(vectors.Length).IsEqualTo(36);
			await Assert.That(Clamp(Required(first.SkRm))).IsEquivalentTo(Convert.FromHexString("4012c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8a48"), CollectionOrdering.Matching);

			foreach (HpkeVector vector in vectors)
			{
				foreach (byte[] privateKey in (byte[][])[Required(vector.SkRm), Clamp(Required(vector.SkRm))])
				{
					using DhKemX25519 recipient = DhKemX25519.ImportDecapsulationKey(privateKey);
					using DhKemX25519? sender = vector.IsAuthenticated ? DhKemX25519.ImportDecapsulationKey(Clamp(Required(vector.SkSm))) : null;
					using DhKemX25519? senderPublic = vector.IsAuthenticated ? DhKemX25519.ImportEncapsulationKey(Required(vector.PkSm)) : null;
					(byte[] enc, byte[] sharedSecret) = sender is null ? Encapsulate(recipient, Required(vector.IkmE)) : AuthEncapsulate(recipient, sender, Required(vector.IkmE));
					byte[] decapsulated = senderPublic is null ? Decapsulate(recipient, Required(vector.Enc)) : TryAuthDecapsulate(recipient, Required(vector.Enc), senderPublic).Output;
					string because = $"{vector} with {Convert.ToHexString(privateKey)}";

					await Assert.That(ExportDecapsulationKey(recipient)).IsEquivalentTo(privateKey, CollectionOrdering.Matching).Because(because);
					await Assert.That(ExportEncapsulationKey(recipient)).IsEquivalentTo(Required(vector.PkRm), CollectionOrdering.Matching).Because(because);
					await Assert.That(enc).IsEquivalentTo(Required(vector.Enc), CollectionOrdering.Matching).Because(because);
					await Assert.That(sharedSecret).IsEquivalentTo(vector.SharedSecret, CollectionOrdering.Matching).Because(because);
					await Assert.That(decapsulated).IsEquivalentTo(vector.SharedSecret, CollectionOrdering.Matching).Because(because);
				}
			}
		}
	}

	// Bit 255 and u ≥ p are taken as RFC 7748 requires, and the shared secret binds the encoding as given, since SerializePublicKey is the identity.
	[Test]
	public async Task PublicKeysInAnyEncodingAreAcceptedAndBoundAsGiven()
	{
		using DhKemX25519 generated = DhKemX25519.GenerateKey();
		byte[] recipientKey = ExportEncapsulationKey(generated);
		byte[] withTopBit = (byte[])recipientKey.Clone();
		withTopBit[31] |= 0x80;
		byte[] reduced = EncodeInteger(P + 2);
		byte[] reducedWithTopBit = (byte[])reduced.Clone();
		reducedWithTopBit[31] |= 0x80;
		byte[] ikmE = CreateDeterministicSource(32);
		byte[] ephemeralKey = HKDF.Expand(HashAlgorithmName.SHA256, LabeledExtract("dkp_prk"u8, ikmE), 32, LabeledInfo("sk"u8, [], 32));

		using (Assert.Multiple())
		{
			foreach (byte[] encoding in (byte[][])[withTopBit, reduced, reducedWithTopBit])
			{
				using DhKemX25519 recipient = DhKemX25519.ImportEncapsulationKey(encoding);
				(byte[] enc, byte[] sharedSecret) = Encapsulate(recipient, ikmE);
				byte[] expected = ExtractAndExpand(X25519Function(ephemeralKey, encoding), [.. enc, .. encoding]);

				await Assert.That(ExportEncapsulationKey(recipient)).IsEquivalentTo(encoding, CollectionOrdering.Matching);
				await Assert.That(enc).IsEquivalentTo(X25519Function(ephemeralKey, Nine), CollectionOrdering.Matching);
				await Assert.That(sharedSecret).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}

			// The key pair binds its canonical encoding, so a sender that used another one disagrees with it.
			using DhKemX25519 nonCanonical = DhKemX25519.ImportEncapsulationKey(withTopBit);
			(byte[] otherEnc, byte[] otherSecret) = Encapsulate(nonCanonical);
			await Assert.That(Decapsulate(generated, otherEnc)).IsNotEquivalentTo(otherSecret);
		}
	}

	// Every encoding of a point whose order divides 8, the bit 255 and u ≥ p forms included: no encapsulation key, and no ciphertext in any mode.
	[Test]
	public async Task PointsOfSmallOrderAreRejected()
	{
		using DhKemX25519 recipient = DhKemX25519.GenerateKey();
		using DhKemX25519 sender = DhKemX25519.GenerateKey();
		byte[] info = "info"u8.ToArray();
		byte[] psk = CreateDeterministicSource(32);
		byte[] pskId = "psk_id"u8.ToArray();

		using (Assert.Multiple())
		{
			foreach (byte[] publicKey in SmallOrderPublicKeys())
			{
				string because = Convert.ToHexString(publicKey);
				(bool result, byte[] output) = TryDecapsulate(recipient, publicKey);
				(bool authResult, byte[] authOutput) = TryAuthDecapsulate(recipient, publicKey, sender);

				await Assert.That(() => DhKemX25519.ImportEncapsulationKey(publicKey)).Throws<ArgumentException>().WithParameterName("source").Because(because);
				await Assert.That((result, authResult)).IsEqualTo((false, false)).Because(because);
				await Assert.That(output).All(static value => value is DestinationSentinel).Because(because);
				await Assert.That(authOutput).All(static value => value is DestinationSentinel).Because(because);

				foreach (HpkeTestMode mode in Enum.GetValues<HpkeTestMode>())
				{
					await Assert.That(TryCreateRecipient(mode, recipient, sender, HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305, publicKey, info, psk, pskId)).IsNull().Because($"{because} in {mode}");
				}
			}
		}
	}

	// decodeScalar25519 of RFC 7748, Section 5.
	private static byte[] Clamp(byte[] privateKey)
	{
		byte[] clamped = (byte[])privateKey.Clone();
		clamped[0] &= 0xF8;
		clamped[31] = (byte)(clamped[31] & 0x7F | 0x40);
		return clamped;
	}

	private static byte[] LabeledExtract(ReadOnlySpan<byte> label, byte[] ikm)
	{
		return HKDF.Extract(HashAlgorithmName.SHA256, [.. "HPKE-v1"u8, .. SuiteId, .. label, .. ikm], []);
	}

	private static byte[] LabeledInfo(ReadOnlySpan<byte> label, byte[] info, int length)
	{
		return [(byte)(length >> 8), (byte)length, .. "HPKE-v1"u8, .. SuiteId, .. label, .. info];
	}

	private static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
	{
		return HKDF.Expand(HashAlgorithmName.SHA256, LabeledExtract("eae_prk"u8, dh), 32, LabeledInfo("shared_secret"u8, kemContext, 32));
	}

	private static byte[] Required(byte[]? value)
	{
		return value ?? throw new InvalidOperationException("The vector lacks a value the test needs.");
	}
}
