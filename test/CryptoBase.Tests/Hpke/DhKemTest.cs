using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.Hpke;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.KeyAgreements.Xdh;
using CryptoBase.Tests.EllipticCurves;
using CryptoBase.Tests.Kems;
using CryptoBase.Tests.KeyAgreements;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.Hpke.HpkeTestUtils;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.KeyAgreements.Ecdh.EcdhTestUtils;
using static CryptoBase.Tests.KeyAgreements.KeyAgreementTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hpke;

// The DHKEM behavior that KemContractTest does not cover: the RFC 9180 formulas on random keys, key derivation, key validation and the authenticated operations. DhKemX25519Test has what is particular to X25519.
[GenerateGenericTest(typeof(DhKemP256), typeof(EcdhP256))]
[GenerateGenericTest(typeof(DhKemP384), typeof(EcdhP384))]
[GenerateGenericTest(typeof(DhKemP521), typeof(EcdhP521))]
[GenerateGenericTest(typeof(DhKemX25519), typeof(X25519))]
[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the keys are disposed.")]
public class DhKemTest<TKem, TEcdh> where TKem : class, IHpkeAuthKem<TKem> where TEcdh : class, IKeyAgreement<TEcdh>
{
	private const int Iterations = 4;

	// kem_id and the hash of the KDF, from RFC 9180, Section 7.1.
	private static (ushort KemId, HashAlgorithmName Hash) Suite => typeof(TKem).Name switch
	{
		nameof(DhKemP256) => (0x0010, HashAlgorithmName.SHA256),
		nameof(DhKemP384) => (0x0011, HashAlgorithmName.SHA384),
		nameof(DhKemP521) => (0x0012, HashAlgorithmName.SHA512),
		nameof(DhKemX25519) => (0x0020, HashAlgorithmName.SHA256),
		_ => throw new NotSupportedException(typeof(TKem).Name)
	};

	[Test]
	public async Task KeysAreThoseOfTheCurve()
	{
		(ushort kemId, HashAlgorithmName hash) = Suite;
		using TKem kem = TKem.GenerateKey();
		using TEcdh ecdh = TEcdh.ImportPrivateKey(ExportDecapsulationKey(kem));

		using (Assert.Multiple())
		{
			await Assert.That(TKem.KemId).IsEqualTo(kemId);
			await Assert.That((TKem.EncapsulationKeyLength, TKem.CiphertextLength)).IsEqualTo((TEcdh.PublicKeyLength, TEcdh.PublicKeyLength));
			await Assert.That((TKem.DecapsulationKeyLength, TKem.PrivateSeedLength)).IsEqualTo((TEcdh.PrivateKeyLength, TEcdh.PrivateKeyLength));
			await Assert.That(TKem.SharedSecretLength).IsEqualTo(HashLength(hash));
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(ExportPublicKey(ecdh), CollectionOrdering.Matching);
		}
	}

	// ExtractAndExpand of RFC 9180, Section 4.1, over the platform's HKDF and the DH values of the ECDH type.
	[Test]
	public async Task SharedSecretsFollowFromTheDiffieHellmanValues()
	{
		for (int i = 0; i < Iterations; ++i)
		{
			using TKem recipient = TKem.GenerateKey();
			using TKem sender = TKem.GenerateKey();
			using TKem senderPublic = TKem.ImportEncapsulationKey(ExportEncapsulationKey(sender));
			using TEcdh recipientEcdh = TEcdh.ImportPrivateKey(ExportDecapsulationKey(recipient));
			byte[] recipientPublicKey = ExportEncapsulationKey(recipient);
			byte[] senderPublicKey = ExportEncapsulationKey(sender);

			(byte[] enc, byte[] sharedSecret) = Encapsulate(recipient);
			(byte[] authEnc, byte[] authSharedSecret) = AuthEncapsulate(recipient, sender);
			byte[] expected = ExtractAndExpand(DeriveSharedSecret(recipientEcdh, enc), [.. enc, .. recipientPublicKey]);
			byte[] dh = [.. DeriveSharedSecret(recipientEcdh, authEnc), .. DeriveSharedSecret(recipientEcdh, senderPublicKey)];
			byte[] expectedAuth = ExtractAndExpand(dh, [.. authEnc, .. recipientPublicKey, .. senderPublicKey]);

			using (Assert.Multiple())
			{
				await Assert.That(sharedSecret).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(recipient, enc)).IsEquivalentTo(expected, CollectionOrdering.Matching);
				await Assert.That(authSharedSecret).IsEquivalentTo(expectedAuth, CollectionOrdering.Matching);
				await Assert.That(TryAuthDecapsulate(recipient, authEnc, senderPublic).Output).IsEquivalentTo(expectedAuth, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task DeriveKeyPairTakesAnyLengthAndKeepsNoSeed()
	{
		int seedLength = TKem.PrivateSeedLength;
		List<byte[]> decapsulationKeys = [];

		using (Assert.Multiple())
		{
			foreach (int length in (int[])[0, 1, seedLength - 1, seedLength, 300])
			{
				byte[] ikm = CreateDeterministicSource(length);
				using TKem derived = TKem.DeriveKeyPair(ikm);
				using TKem again = TKem.DeriveKeyPair(ikm);
				byte[] decapsulationKey = ExportDecapsulationKey(derived);
				decapsulationKeys.Add(decapsulationKey);

				await Assert.That((derived.HasPrivateSeed, derived.HasDecapsulationKey)).IsEqualTo((false, true));
				await Assert.That(ExportDecapsulationKey(again)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
				await Assert.That(() => derived.ExportPrivateSeed(new byte[seedLength])).ThrowsExactly<InvalidOperationException>();

				if (length == seedLength)
				{
					using TKem fromSeed = TKem.ImportPrivateSeed(ikm);
					await Assert.That(fromSeed.HasPrivateSeed).IsTrue();
					await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(ikm, CollectionOrdering.Matching);
					await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
				}
			}

			await Assert.That(decapsulationKeys.Select(Convert.ToHexString)).HasDistinctItems();
		}
	}

	[Test]
	public async Task GeneratedKeysAreDerivedFromTheirSeeds()
	{
		for (int i = 0; i < Iterations; ++i)
		{
			using TKem generated = TKem.GenerateKey();
			using TKem derived = TKem.DeriveKeyPair(ExportPrivateSeed(generated));

			await Assert.That(ExportDecapsulationKey(derived)).IsEquivalentTo(ExportDecapsulationKey(generated), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task InvalidKeysThrow()
	{
		KeyAgreementChecks checks = KeyAgreementChecks.Of<TEcdh>();

		using (Assert.Multiple())
		{
			foreach (byte[] privateKey in checks.InvalidPrivateKeys)
			{
				await Assert.That(() => TKem.ImportDecapsulationKey(privateKey)).Throws<ArgumentException>().WithParameterName("source");
			}

			foreach (byte[] publicKey in checks.InvalidPublicKeys)
			{
				await Assert.That(() => TKem.ImportEncapsulationKey(publicKey)).Throws<ArgumentException>().WithParameterName("source");
			}

			foreach ((byte[] privateKey, byte[] publicKey) in ExtremeKeyPairs())
			{
				using TKem kem = TKem.ImportDecapsulationKey(privateKey);
				await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task AuthenticationBindsTheSender()
	{
		using TKem recipient = TKem.GenerateKey();
		using TKem sender = TKem.GenerateKey();
		using TKem other = TKem.GenerateKey();
		(byte[] enc, byte[] sharedSecret) = AuthEncapsulate(recipient, sender);
		(bool otherResult, byte[] otherSecret) = TryAuthDecapsulate(recipient, enc, other);

		using (Assert.Multiple())
		{
			await Assert.That(TryAuthDecapsulate(recipient, enc, sender).Output).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
			await Assert.That(otherResult).IsTrue();
			await Assert.That(otherSecret).IsNotEquivalentTo(sharedSecret);
			await Assert.That(Decapsulate(recipient, enc)).IsNotEquivalentTo(sharedSecret);
		}
	}

	[Test]
	public async Task AuthenticatedOperationsCheckTheirArguments()
	{
		using TKem recipient = TKem.GenerateKey();
		using TKem sender = TKem.GenerateKey();
		using TKem recipientPublic = TKem.ImportEncapsulationKey(ExportEncapsulationKey(recipient));
		using TKem senderPublic = TKem.ImportEncapsulationKey(ExportEncapsulationKey(sender));
		TKem disposed = TKem.GenerateKey();
		disposed.Dispose();
		byte[] enc = AuthEncapsulate(recipient, sender).Enc;
		byte[] ciphertext = CreateGuardedBuffer(0, TKem.CiphertextLength);
		byte[] sharedSecret = CreateGuardedBuffer(0, TKem.SharedSecretLength);
		byte[] shortCiphertext = ShortBuffer(TKem.CiphertextLength, 1);
		byte[] shortSecret = ShortBuffer(TKem.SharedSecretLength, 1);
		byte[] overlapping = CreateGuardedBuffer(0, TKem.CiphertextLength + TKem.SharedSecretLength);

		using (Assert.Multiple())
		{
			await Assert.That(() => recipient.AuthEncapsulate(null!, ciphertext, sharedSecret)).Throws<ArgumentNullException>().WithParameterName("sender");
			await Assert.That(() => recipient.TryAuthDecapsulate(enc, null!, sharedSecret)).Throws<ArgumentNullException>().WithParameterName("sender");
			await Assert.That(() => recipient.AuthEncapsulate(senderPublic, ciphertext, sharedSecret)).ThrowsExactly<ArgumentException>().WithParameterName("sender");
			await Assert.That(() => recipient.AuthEncapsulate(disposed, ciphertext, sharedSecret)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipient.TryAuthDecapsulate(enc, disposed, sharedSecret)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => disposed.AuthEncapsulate(sender, ciphertext, sharedSecret)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => disposed.TryAuthDecapsulate(enc, sender, sharedSecret)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => recipientPublic.TryAuthDecapsulate(enc, sender, sharedSecret)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => recipient.AuthEncapsulate(sender, shortCiphertext, sharedSecret)).Throws<ArgumentException>().WithParameterName("ciphertext");
			await Assert.That(() => recipient.AuthEncapsulate(sender, ciphertext, shortSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");
			await Assert.That(() => recipient.AuthEncapsulate(sender, overlapping.AsSpan(0, TKem.CiphertextLength), overlapping.AsSpan(TKem.CiphertextLength - 1, TKem.SharedSecretLength))).Throws<ArgumentException>().WithParameterName("sharedSecret");
			await Assert.That(() => recipient.TryAuthDecapsulate(enc, sender, shortSecret)).Throws<ArgumentException>().WithParameterName("sharedSecret");

			foreach (byte[] buffer in (byte[][])[ciphertext, sharedSecret, shortCiphertext, shortSecret, overlapping])
			{
				await Assert.That(buffer).All(static value => value is DestinationSentinel);
			}

			foreach (byte[] invalid in (byte[][])[[], Resize(enc, -1), Resize(enc, 1), .. KemCiphertextChecks.Of<TKem>().InvalidCiphertexts])
			{
				(bool result, byte[] output) = TryAuthDecapsulate(recipient, invalid, sender);
				await Assert.That(result).IsFalse();
				await Assert.That(output).All(static value => value is DestinationSentinel);
			}
		}

		// Decapsulation may write over the ciphertext; the public key of the sender may be the recipient's own.
		byte[] inPlace = [.. enc, .. new byte[TKem.SharedSecretLength]];
		bool decapsulated = recipient.TryAuthDecapsulate(inPlace.AsSpan(0, TKem.CiphertextLength), sender, inPlace.AsSpan(1, TKem.SharedSecretLength));
		(byte[] selfEnc, byte[] selfSecret) = AuthEncapsulate(recipient, recipient);

		using (Assert.Multiple())
		{
			await Assert.That(decapsulated).IsTrue();
			await Assert.That(inPlace.AsSpan(1, TKem.SharedSecretLength).ToArray()).IsEquivalentTo(TryAuthDecapsulate(recipient, enc, sender).Output, CollectionOrdering.Matching);
			await Assert.That(TryAuthDecapsulate(recipient, selfEnc, recipientPublic).Output).IsEquivalentTo(selfSecret, CollectionOrdering.Matching);
		}
	}

	// Decapsulation keys at the ends of their range, with their encapsulation keys: d = 1 and n − 1 on a curve, and for X25519 the keys of all zeros and all ones.
	private static (byte[] PrivateKey, byte[] PublicKey)[] ExtremeKeyPairs()
	{
		if (typeof(TEcdh) == typeof(X25519))
		{
			byte[] nine = EncodeInteger(9);
			return [.. ((byte[][])[new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray()]).Select(privateKey => (privateKey, X25519Function(privateKey, nine)))];
		}

		CurveCase curve = CurveOf<TEcdh>();
		CurvePoint g = curve.Reference.Generator;
		return [(curve.EncodeScalar(BigInteger.One), curve.EncodePoint(g)), (curve.EncodeScalar(curve.Order - 1), curve.EncodePoint(g with { Y = curve.Reference.P - g.Y }))];
	}

	private static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
	{
		(ushort kemId, HashAlgorithmName hash) = Suite;
		int length = TKem.SharedSecretLength;
		byte[] suiteId = [.. "KEM"u8, (byte)(kemId >> 8), (byte)kemId];
		byte[] prk = HKDF.Extract(hash, [.. "HPKE-v1"u8, .. suiteId, .. "eae_prk"u8, .. dh], []);
		return HKDF.Expand(hash, prk, length, [(byte)(length >> 8), (byte)length, .. "HPKE-v1"u8, .. suiteId, .. "shared_secret"u8, .. kemContext]);
	}

	private static int HashLength(HashAlgorithmName hash)
	{
		return hash == HashAlgorithmName.SHA256 ? 32 : hash == HashAlgorithmName.SHA384 ? 48 : 64;
	}
}
