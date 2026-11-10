using CryptoBase.Hpke;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.Tests.Wycheproof;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.KeyAgreements.Xdh.X448TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hpke;

public class DhKemX448Test
{
	private static readonly byte[] SuiteId = [.. "KEM"u8, 0x00, 0x21];
	private static readonly byte[] Five = EncodeInteger(5);

	// RFC 9180, Sec. 7.1.3.
	[Test]
	public async Task DeriveKeyPairExpandsAnyInputIntoTheKey()
	{
		byte[][] inputs = [[], [0x00], CreateDeterministicSource(55), new byte[56], Enumerable.Repeat((byte)0xFF, 56).ToArray(), CreateDeterministicSource(57), CreateDeterministicSource(130), CreateDeterministicSource(1000)];

		using (Assert.Multiple())
		{
			foreach (byte[] ikm in inputs)
			{
				byte[] privateKey = HKDF.Expand(HashAlgorithmName.SHA512, LabeledExtract("dkp_prk"u8, ikm), 56, LabeledInfo("sk"u8, [], 56));
				using DhKemX448 derived = DhKemX448.DeriveKeyPair(ikm);

				await Assert.That(ExportDecapsulationKey(derived)).IsEquivalentTo(privateKey, CollectionOrdering.Matching).Because($"ikm of {ikm.Length} bytes");
				await Assert.That(ExportEncapsulationKey(derived)).IsEquivalentTo(X448Function(privateKey, Five), CollectionOrdering.Matching).Because($"ikm of {ikm.Length} bytes");

				if (ikm.Length == DhKemX448.PrivateSeedLength)
				{
					using DhKemX448 fromSeed = DhKemX448.ImportPrivateSeed(ikm);
					await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(ikm, CollectionOrdering.Matching);
					await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				}
			}
		}
	}

	// RFC 9180, Sec. 7.1.2 serializes the clamped form, which must be the same key.
	[Test]
	public async Task DecapsulationKeysExportAsImportedAndClampingKeepsThem()
	{
		HpkeVector[] vectors = [.. HpkeVectors.Full().Where(static vector => vector.KemId is 0x0021)];
		HpkeVector first = vectors.First(static vector => vector is { Source: "RFC 9180", Mode: 0, Kdf: HpkeKdfId.HkdfSha512, Aead: HpkeAeadId.ChaCha20Poly1305 });

		using (Assert.Multiple())
		{
			await Assert.That(vectors.Length).IsEqualTo(32);
			await Assert.That(Clamp(Required(first.SkRm))).IsEquivalentTo(Convert.FromHexString("c0f51845154d6bb6917e44ef0fa0a1fbf1d80f61d199486e75295e8a7e50432d548a7f8040953826c4f1bce79e433dedb4469391c3cc98a1"), CollectionOrdering.Matching);

			foreach (HpkeVector vector in vectors)
			{
				foreach (byte[] privateKey in (byte[][])[Required(vector.SkRm), Clamp(Required(vector.SkRm))])
				{
					using DhKemX448 recipient = DhKemX448.ImportDecapsulationKey(privateKey);
					using DhKemX448? sender = vector.IsAuthenticated ? DhKemX448.ImportDecapsulationKey(Clamp(Required(vector.SkSm))) : null;
					using DhKemX448? senderPublic = vector.IsAuthenticated ? DhKemX448.ImportEncapsulationKey(Required(vector.PkSm)) : null;
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

	// SerializePublicKey is the identity, so the shared secret binds the encoding; 2 is on the curve and 6 on the twist.
	[Test]
	public async Task PublicKeysInAnyEncodingAreAcceptedAndBoundAsGiven()
	{
		byte[] canonical = EncodeInteger(2);
		byte[] reduced = EncodeInteger(P + 2);
		byte[][] encodings = [canonical, reduced, EncodeInteger(6), EncodeInteger(P + 6), EncodeInteger((BigInteger.One << 448) - 1)];
		byte[] ikmE = CreateDeterministicSource(56);
		byte[] ephemeralKey = HKDF.Expand(HashAlgorithmName.SHA512, LabeledExtract("dkp_prk"u8, ikmE), 56, LabeledInfo("sk"u8, [], 56));
		List<byte[]> sharedSecrets = [];

		using (Assert.Multiple())
		{
			await Assert.That((IsSquare(8 + 156326 * 4 + 2), IsSquare(216 + 156326 * 36 + 6))).IsEqualTo((true, false));

			foreach (byte[] encoding in encodings)
			{
				using DhKemX448 recipient = DhKemX448.ImportEncapsulationKey(encoding);
				(byte[] enc, byte[] sharedSecret) = Encapsulate(recipient, ikmE);
				byte[] expected = ExtractAndExpand(X448Function(ephemeralKey, encoding), [.. enc, .. encoding]);
				sharedSecrets.Add(sharedSecret);

				await Assert.That(ExportEncapsulationKey(recipient)).IsEquivalentTo(encoding, CollectionOrdering.Matching);
				await Assert.That(enc).IsEquivalentTo(X448Function(ephemeralKey, Five), CollectionOrdering.Matching);
				await Assert.That(sharedSecret).IsEquivalentTo(expected, CollectionOrdering.Matching);
			}

			await Assert.That(X448Function(ephemeralKey, reduced)).IsEquivalentTo(X448Function(ephemeralKey, canonical), CollectionOrdering.Matching);
			await Assert.That(sharedSecrets[1]).IsNotEquivalentTo(sharedSecrets[0]);
		}
	}

	[Test]
	public async Task DecapsulationTakesAnyEncoding()
	{
		byte[][] encodings = [EncodeInteger(P + 2), EncodeInteger(6), EncodeInteger(P + 6), EncodeInteger((BigInteger.One << 448) - 1)];
		using DhKemX448 recipient = DhKemX448.GenerateKey();
		byte[] privateKey = ExportDecapsulationKey(recipient);
		byte[] publicKey = ExportEncapsulationKey(recipient);

		using (Assert.Multiple())
		{
			for (int i = 0; i < encodings.Length; ++i)
			{
				byte[] enc = encodings[i];
				byte[] senderKey = encodings[(i + 1) % encodings.Length];
				using DhKemX448 sender = DhKemX448.ImportEncapsulationKey(senderKey);
				(bool result, byte[] output) = TryDecapsulate(recipient, enc);
				(bool authResult, byte[] authOutput) = TryAuthDecapsulate(recipient, enc, sender);
				byte[] expectedAuth = ExtractAndExpand([.. X448Function(privateKey, enc), .. X448Function(privateKey, senderKey)], [.. enc, .. publicKey, .. senderKey]);
				string because = $"{Convert.ToHexString(enc)} from {Convert.ToHexString(senderKey)}";

				await Assert.That((result, authResult)).IsEqualTo((true, true)).Because(because);
				await Assert.That(output).IsEquivalentTo(ExtractAndExpand(X448Function(privateKey, enc), [.. enc, .. publicKey]), CollectionOrdering.Matching).Because(because);
				await Assert.That(authOutput).IsEquivalentTo(expectedAuth, CollectionOrdering.Matching).Because(because);
			}
		}
	}

	[Test]
	public async Task PointsOfSmallOrderAreRejected()
	{
		using DhKemX448 recipient = DhKemX448.GenerateKey();
		using DhKemX448 sender = DhKemX448.GenerateKey();
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

				await Assert.That(() => DhKemX448.ImportEncapsulationKey(publicKey)).Throws<ArgumentException>().WithParameterName("source").Because(because);
				await Assert.That((result, authResult)).IsEqualTo((false, false)).Because(because);
				await Assert.That(output).All(static value => value is DestinationSentinel).Because(because);
				await Assert.That(authOutput).All(static value => value is DestinationSentinel).Because(because);

				foreach (HpkeTestMode mode in Enum.GetValues<HpkeTestMode>())
				{
					await Assert.That(TryCreateRecipient(mode, recipient, sender, HpkeKdfId.HkdfSha512, HpkeAeadId.ChaCha20Poly1305, publicKey, info, psk, pskId)).IsNull().Because($"{because} in {mode}");
				}
			}
		}
	}

	// Twist points that Wycheproof flags LowOrderPublic have large order and are accepted.
	[Test]
	public async Task WycheproofPublicKeysAreRejectedJustForAnAllZeroSecret()
	{
		List<string> failures = [];
		int rejected = 0;

		foreach (XdhTestVector vector in WycheproofVectors.Load<XdhTestVector>("x448_test.json").Where(static vector => vector.Public.Length is 56))
		{
			bool zero = !vector.Shared.AsSpan().ContainsAnyExcept((byte)0);
			bool imported;

			try
			{
				using DhKemX448 key = DhKemX448.ImportEncapsulationKey(vector.Public);
				imported = true;
			}
			catch (ArgumentException)
			{
				imported = false;
			}

			rejected += imported ? 0 : 1;

			if (imported == zero)
			{
				failures.Add(Convert.ToHexString(vector.Public));
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(rejected).IsPositive();
		}
	}

	// 4L survives clamping and gives an all-zero public key.
	[Test]
	public async Task TheClampedMultipleOfTheOrderIsNoDecapsulationKey()
	{
		byte[] clamped = EncodeInteger(4 * L);
		List<byte[]> forms = [];

		for (int low = 0; low < 4; ++low)
		{
			foreach (byte top in (byte[])[0x00, 0x80])
			{
				byte[] form = (byte[])clamped.Clone();
				form[0] |= (byte)low;
				form[55] = (byte)(form[55] & 0x7F | top);
				forms.Add(form);
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(forms.Select(Convert.ToHexString)).HasDistinctItems();

			foreach (byte[] form in forms)
			{
				string because = Convert.ToHexString(form);
				using X448 x448 = X448.ImportPrivateKey(form);

				await Assert.That(DecodeScalar(form)).IsEqualTo(4 * L).Because(because);
				await Assert.That(ExportPublicKey(x448)).IsEquivalentTo(new byte[56], CollectionOrdering.Matching).Because(because);
				await Assert.That(() => DhKemX448.ImportDecapsulationKey(form)).Throws<ArgumentException>().WithParameterName("source").Because(because);
			}
		}
	}

	private static byte[] LabeledExtract(ReadOnlySpan<byte> label, byte[] ikm)
	{
		return HKDF.Extract(HashAlgorithmName.SHA512, [.. "HPKE-v1"u8, .. SuiteId, .. label, .. ikm], []);
	}

	private static byte[] LabeledInfo(ReadOnlySpan<byte> label, byte[] info, int length)
	{
		return [(byte)(length >> 8), (byte)length, .. "HPKE-v1"u8, .. SuiteId, .. label, .. info];
	}

	private static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
	{
		return HKDF.Expand(HashAlgorithmName.SHA512, LabeledExtract("eae_prk"u8, dh), 64, LabeledInfo("shared_secret"u8, kemContext, 64));
	}

	private static byte[] Required(byte[]? value)
	{
		return value ?? throw new InvalidOperationException("The vector lacks a value the test needs.");
	}
}
