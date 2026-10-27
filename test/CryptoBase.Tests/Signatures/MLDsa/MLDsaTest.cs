using CryptoBase.Internal;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Tests.Hashes.Sha3;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.MLDsa.MLDsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.MLDsa;

// The behavior of ML-DSA beyond ISignatureKey; SignatureKeyContractTest checks the rest, and the Wycheproof and differential tests the values.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(MLDsa44))]
[GenerateGenericTest(typeof(MLDsa65))]
[GenerateGenericTest(typeof(MLDsa87))]
internal class MLDsaTest<T> where T : class, IMLDsa<T>
{
	private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

	[Test]
	public async Task EveryKeyFormatRoundTrips()
	{
		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);

		using T fromSeed = T.ImportPrivateSeed(seed);
		using T fromPrivateKey = T.ImportPrivateKey(privateKey);
		using T fromPublicKey = T.ImportPublicKey(publicKey);

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateSeed(fromSeed)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(fromSeed)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromSeed)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(fromPrivateKey)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromPrivateKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(ExportPublicKey(fromPublicKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}

		// Every instance verifies what every instance with the private key signs.
		T[] signers = [generated, fromSeed, fromPrivateKey];
		byte[] message = CreateDeterministicSource(100);

		foreach (T signer in signers)
		{
			byte[] signature = Sign(signer, message);

			using (Assert.Multiple())
			{
				foreach (T verifier in (T[])[.. signers, fromPublicKey])
				{
					await Assert.That(verifier.Verify(message, signature)).IsTrue();
				}
			}
		}
	}

	[Test]
	public async Task ReportsWhichKeysItHolds()
	{
		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] algorithmIdentifier = AlgorithmIdentifier<T>();

		using T fromSeed = T.ImportPrivateSeed(seed);
		using T fromPrivateKey = T.ImportPrivateKey(privateKey);
		using T fromPublicKey = T.ImportPublicKey(ExportPublicKey(generated));
		using T fromSubjectPublicKeyInfo = T.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(generated));
		using T fromSeedPkcs8 = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed)));
		using T fromExpandedPkcs8 = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice(privateKey)));
		using T fromBothPkcs8 = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, BothChoice(seed, privateKey)));

		using (Assert.Multiple())
		{
			await Assert.That((generated.HasPrivateSeed, generated.HasPrivateKey)).IsEqualTo((true, true));
			await Assert.That((fromSeed.HasPrivateSeed, fromSeed.HasPrivateKey)).IsEqualTo((true, true));
			await Assert.That((fromPrivateKey.HasPrivateSeed, fromPrivateKey.HasPrivateKey)).IsEqualTo((false, true));
			await Assert.That((fromPublicKey.HasPrivateSeed, fromPublicKey.HasPrivateKey)).IsEqualTo((false, false));
			await Assert.That((fromSubjectPublicKeyInfo.HasPrivateSeed, fromSubjectPublicKeyInfo.HasPrivateKey)).IsEqualTo((false, false));
			await Assert.That((fromSeedPkcs8.HasPrivateSeed, fromSeedPkcs8.HasPrivateKey)).IsEqualTo((true, true));
			await Assert.That((fromExpandedPkcs8.HasPrivateSeed, fromExpandedPkcs8.HasPrivateKey)).IsEqualTo((false, true));
			await Assert.That((fromBothPkcs8.HasPrivateSeed, fromBothPkcs8.HasPrivateKey)).IsEqualTo((true, true));
		}
	}

	// The seed form when the instance holds the seed, the expandedKey form otherwise (RFC 9881, Sec. 6).
	[Test]
	public async Task ExportsTheEncodingsOfRfc9881()
	{
		using T generated = T.GenerateKey();
		using T fromPrivateKey = T.ImportPrivateKey(ExportPrivateKey(generated));
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		byte[] algorithmIdentifier = AlgorithmIdentifier<T>();
		byte[] seedPkcs8 = OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed));

		using (Assert.Multiple())
		{
			await Assert.That(seedPkcs8.Length).IsEqualTo(54);
			await Assert.That(ExportPkcs8PrivateKey(generated)).IsEquivalentTo(seedPkcs8, CollectionOrdering.Matching);
			await Assert.That(ExportPkcs8PrivateKey(fromPrivateKey)).IsEquivalentTo(OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice(privateKey)), CollectionOrdering.Matching);
			await Assert.That(ExportSubjectPublicKeyInfo(generated)).IsEquivalentTo(SubjectPublicKeyInfo(algorithmIdentifier, publicKey), CollectionOrdering.Matching);
			await Assert.That(generated.Pkcs8PrivateKeyLength).IsEqualTo(54);
			await Assert.That(fromPrivateKey.Pkcs8PrivateKeyLength).IsEqualTo(OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice(privateKey)).Length);
		}
	}

	[Test]
	public async Task ImportsTheEncodingsOfRfc9881()
	{
		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		byte[] algorithmIdentifier = AlgorithmIdentifier<T>();

		// A version 2 OneAsymmetricKey may carry the public key, and any key may carry attributes.
		using T withPublicKey = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), publicKey));
		using T withAttributes = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice(privateKey), attributes: [0xA0, 0x00]));
		using T withTwoAttributes = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x12, 0x30, 0x07, 0x06, 0x01, 0x2A, 0x31, 0x02, 0x05, 0x00, 0x30, 0x07, 0x06, 0x01, 0x2B, 0x31, 0x02, 0x05, 0x00]));
		using T fromBoth = T.ImportPkcs8PrivateKey(OneAsymmetricKey(algorithmIdentifier, BothChoice(seed, privateKey), publicKey, [0xA0, 0x00]));

		using (Assert.Multiple())
		{
			await Assert.That(ExportPrivateSeed(withPublicKey)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(withAttributes)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateSeed(withTwoAttributes)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateSeed(fromBoth)).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateKey(fromBoth)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task RejectsMalformedOrInconsistentEncodings()
	{
		using T generated = T.GenerateKey();
		using T other = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		byte[] algorithmIdentifier = AlgorithmIdentifier<T>();
		byte[] withParameters = [0x30, 0x0D, .. algorithmIdentifier.AsSpan(2), 0x05, 0x00];
		byte[] otherAlgorithm = (byte[])algorithmIdentifier.Clone();
		otherAlgorithm[^1] ^= 3;
		byte[] seedPkcs8 = OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed));
		byte[] subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKey);

		byte[][] privateKeys =
		[
			// The seed and the expanded key must agree (RFC 9881, Sec. 8.2), as must the public key.
			OneAsymmetricKey(algorithmIdentifier, BothChoice(ExportPrivateSeed(other), privateKey)),
			OneAsymmetricKey(algorithmIdentifier, BothChoice(seed, Flip(privateKey, 40))),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), ExportPublicKey(other)),
			OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice(privateKey), Flip(publicKey, 100)),
			// An empty publicKey is not an absent one.
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), []),
			// Attributes must be a DER SET OF Attribute: truncated, without a type, without values, unsorted.
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x01, 0xFF]),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x01, 0x30]),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x02, 0x30, 0x00]),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2A]),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), attributes: [0xA0, 0x0E, 0x30, 0x05, 0x06, 0x01, 0x2B, 0x31, 0x00, 0x30, 0x05, 0x06, 0x01, 0x2A, 0x31, 0x00]),
			// Each part must have its length.
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed.AsSpan(1).ToArray())),
			OneAsymmetricKey(algorithmIdentifier, ExpandedKeyChoice([.. privateKey, 0])),
			OneAsymmetricKey(algorithmIdentifier, BothChoice(seed, privateKey.AsSpan(1).ToArray())),
			// Only the three choices, each alone.
			OneAsymmetricKey(algorithmIdentifier, [.. SeedChoice(seed), 0x05, 0x00]),
			OneAsymmetricKey(algorithmIdentifier, [0x81, .. SeedChoice(seed).AsSpan(1)]),
			// The seed takes the IMPLICIT tag [0], not an EXPLICIT one around an OCTET STRING.
			OneAsymmetricKey(algorithmIdentifier, [0xA0, 0x22, 0x04, 0x20, .. seed]),
			OneAsymmetricKey(algorithmIdentifier, []),
			// The version is v1 (0) or v2 (1), and only v2 carries a publicKey.
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), version: 2),
			OneAsymmetricKey(algorithmIdentifier, SeedChoice(seed), publicKey, version: 0),
			OneAsymmetricKey(withParameters, SeedChoice(seed)),
			OneAsymmetricKey(otherAlgorithm, SeedChoice(seed)),
			[.. seedPkcs8, 0],
			seedPkcs8.AsSpan(0, seedPkcs8.Length - 1).ToArray(),
			// A long-form length where the short form fits is not DER.
			[0x30, 0x81, (byte)(seedPkcs8.Length - 2), .. seedPkcs8.AsSpan(2)],
			subjectPublicKeyInfo,
			seed,
			privateKey
		];

		byte[][] subjectPublicKeyInfos =
		[
			SubjectPublicKeyInfo(withParameters, publicKey),
			SubjectPublicKeyInfo(otherAlgorithm, publicKey),
			SubjectPublicKeyInfo(algorithmIdentifier, publicKey.AsSpan(1).ToArray()),
			SubjectPublicKeyInfo(algorithmIdentifier, [.. publicKey, 0]),
			[.. subjectPublicKeyInfo, 0],
			subjectPublicKeyInfo.AsSpan(0, subjectPublicKeyInfo.Length - 1).ToArray(),
			// A BIT STRING with unused bits.
			[.. subjectPublicKeyInfo.AsSpan(0, subjectPublicKeyInfo.Length - publicKey.Length - 1), 1, .. publicKey.AsSpan(0, publicKey.Length - 1), 0],
			seedPkcs8,
			publicKey
		];

		using (Assert.Multiple())
		{
			for (int i = 0; i < privateKeys.Length; ++i)
			{
				byte[] encoding = privateKeys[i];
				await Assert.That(() => T.ImportPkcs8PrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"private key {i}");
			}

			for (int i = 0; i < subjectPublicKeyInfos.Length; ++i)
			{
				byte[] encoding = subjectPublicKeyInfos[i];
				await Assert.That(() => T.ImportSubjectPublicKeyInfo(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"public key {i}");
			}
		}
	}

	// s1 and s2 outside [−η, η], or t0 or tr that do not follow from ρ, s1 and s2; K is free.
	[Test]
	public async Task RejectsInconsistentPrivateKeys()
	{
		(int k, int l, int eta, _) = Parameters<T>();
		int etaLength = eta is 2 ? 96 : 128;
		using T generated = T.GenerateKey();
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] message = CreateDeterministicSource(10);

		byte[] s1 = (byte[])privateKey.Clone();
		s1[128] = 0xFF;
		byte[] s2 = (byte[])privateKey.Clone();
		s2[128 + l * etaLength + etaLength - 1] = 0xFF;
		byte[][] invalid = [s1, s2, Flip(privateKey, 0), Flip(privateKey, 64), Flip(privateKey, 127), Flip(privateKey, privateKey.Length - 1), Flip(privateKey, 128 + (l + k) * etaLength)];

		using T otherSigningSeed = T.ImportPrivateKey(Flip(privateKey, 32));
		byte[] randomness = new byte[32];

		using (Assert.Multiple())
		{
			for (int i = 0; i < invalid.Length; ++i)
			{
				byte[] encoding = invalid[i];
				await Assert.That(() => T.ImportPrivateKey(encoding)).Throws<ArgumentException>().WithParameterName("source").Because($"private key {i}");
			}

			await Assert.That(generated.Verify(message, Sign(otherSigningSeed, message))).IsTrue();
			await Assert.That(SignWithRandomness(otherSigningSeed, message, [], randomness)).IsNotEquivalentTo(SignWithRandomness(generated, message, [], randomness));
		}
	}

	[Test]
	public async Task MissingKeysThrowInvalidOperation()
	{
		using T generated = T.GenerateKey();
		using T fromPrivateKey = T.ImportPrivateKey(ExportPrivateKey(generated));
		using T fromPublicKey = T.ImportPublicKey(ExportPublicKey(generated));
		byte[] seed = CreateGuardedBuffer(0, T.PrivateSeedLength);
		byte[] privateKey = CreateGuardedBuffer(0, T.PrivateKeyLength);
		byte[] signature = CreateGuardedBuffer(0, T.SignatureLength);
		byte[] mu = new byte[T.MuLength];
		byte[] hash = new byte[64];

		using (Assert.Multiple())
		{
			await Assert.That(() => fromPrivateKey.ExportPrivateSeed(seed)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromPublicKey.ExportPrivateSeed(seed)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromPublicKey.ExportPrivateKey(privateKey)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromPublicKey.Sign(mu, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromPublicKey.SignPreHash(hash, signature, Sha512Oid)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => fromPublicKey.SignMu(mu, signature)).ThrowsExactly<InvalidOperationException>();
			await Assert.That(seed).All(static value => value is DestinationSentinel);
			await Assert.That(privateKey).All(static value => value is DestinationSentinel);
			await Assert.That(signature).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task ShortOutputsThrowAndStayUnchanged()
	{
		using T key = T.GenerateKey();
		byte[] mu = new byte[T.MuLength];
		byte[] hash = new byte[64];

		foreach (int shortfall in (int[])[1, int.MaxValue])
		{
			byte[] seed = ShortBuffer(T.PrivateSeedLength, shortfall);
			byte[] privateKey = ShortBuffer(T.PrivateKeyLength, shortfall);
			byte[] publicKey = ShortBuffer(T.PublicKeyLength, shortfall);
			byte[] signature = ShortBuffer(T.SignatureLength, shortfall);

			using (Assert.Multiple())
			{
				await Assert.That(() => key.ExportPrivateSeed(seed)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportPrivateKey(privateKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.ExportPublicKey(publicKey)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.Sign(mu, signature)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.SignPreHash(hash, signature, Sha512Oid)).Throws<ArgumentException>().WithParameterName("destination");
				await Assert.That(() => key.SignMu(mu, signature)).Throws<ArgumentException>().WithParameterName("destination");

				foreach (byte[] buffer in (byte[][])[seed, privateKey, publicKey, signature])
				{
					await Assert.That(buffer).All(static value => value is DestinationSentinel);
				}
			}
		}
	}

	[Test]
	public async Task InputsOfTheWrongLengthThrow()
	{
		using T key = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(key);
		byte[] privateKey = ExportPrivateKey(key);
		byte[] publicKey = ExportPublicKey(key);
		byte[] message = CreateDeterministicSource(10);
		byte[] mu = Mu(publicKey, message);
		byte[] hash = new byte[64];
		byte[] signature = CreateGuardedBuffer(0, T.SignatureLength);
		byte[] longContext = new byte[T.MaxContextLength + 1];

		using (Assert.Multiple())
		{
			foreach (int delta in (int[])[-1, 1])
			{
				await Assert.That(() => T.ImportPrivateSeed(Resize(seed, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportPrivateKey(Resize(privateKey, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => T.ImportPublicKey(Resize(publicKey, delta))).Throws<ArgumentException>().WithParameterName("source");
				await Assert.That(() => key.SignMu(Resize(mu, delta), signature)).Throws<ArgumentException>().WithParameterName("mu");
				await Assert.That(() => key.VerifyMu(Resize(mu, delta), signature)).Throws<ArgumentException>().WithParameterName("mu");
				await Assert.That(() => key.SignPreHash(Resize(hash, delta), signature, Sha512Oid)).Throws<ArgumentException>().WithParameterName("hash");
				await Assert.That(() => key.VerifyPreHash(Resize(hash, delta), signature, Sha512Oid)).Throws<ArgumentException>().WithParameterName("hash");
			}

			await Assert.That(() => T.ImportPrivateSeed([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportPrivateKey([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => T.ImportPublicKey([])).Throws<ArgumentException>().WithParameterName("source");
			await Assert.That(() => key.Sign(message, signature, longContext)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");
			await Assert.That(() => key.Verify(message, signature, longContext)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");
			await Assert.That(() => key.SignPreHash(hash, signature, Sha512Oid, longContext)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");
			await Assert.That(() => key.VerifyPreHash(hash, signature, Sha512Oid, longContext)).Throws<ArgumentOutOfRangeException>().WithParameterName("context");

			// Unknown hashes, and the 224-bit ones, which no parameter set accepts.
			foreach (string oid in (string[])["1.2.3", "2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.13", "2.16.840.1.101.3.4.2.01", ""])
			{
				await Assert.That(() => key.SignPreHash(hash, signature, oid)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid");
				await Assert.That(() => key.VerifyPreHash(hash, signature, oid)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid");
			}

			await Assert.That(() => key.SignPreHash(hash, signature, null!)).Throws<ArgumentNullException>().WithParameterName("hashAlgorithmOid");
			await Assert.That(() => key.VerifyPreHash(hash, signature, null!)).Throws<ArgumentNullException>().WithParameterName("hashAlgorithmOid");
			await Assert.That(signature).All(static value => value is DestinationSentinel);
		}

		// A signature of the wrong length is invalid rather than an error.
		byte[] valid = Sign(key, message);

		using (Assert.Multiple())
		{
			foreach (byte[] wrong in (byte[][])[Resize(valid, -1), Resize(valid, 1), []])
			{
				await Assert.That(key.Verify(message, wrong)).IsFalse();
				await Assert.That(key.VerifyMu(mu, wrong)).IsFalse();
				await Assert.That(key.VerifyPreHash(hash, wrong, Sha512Oid)).IsFalse();
			}
		}
	}

	// The context, the mode and the hash each separate signatures; μ joins the message methods to the μ methods.
	[Test]
	public async Task SignaturesAreBoundToTheirInputs()
	{
		using T key = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(key);
		byte[] message = CreateDeterministicSource(50);
		byte[] context = [1, 2, 3];
		byte[] hash = SHA512.HashData(message);
		byte[] pure = Sign(key, message, context);
		byte[] preHash = SignPreHash(key, hash, Sha512Oid, context);
		byte[] fromMu = SignMu(key, Mu(publicKey, message, context));
		byte[] fromPreHashMu = SignMu(key, PreHashMu(publicKey, hash, 3, context));
		byte[] fromAlgorithm = Sign(key, AlgorithmsOf<T>()[0], message);

		using (Assert.Multiple())
		{
			await Assert.That(key.Verify(message, pure, context)).IsTrue();
			await Assert.That(key.Verify(message, pure)).IsFalse();
			await Assert.That(key.Verify(message, pure, [1, 2])).IsFalse();
			await Assert.That(key.Verify(message.AsSpan(1), pure, context)).IsFalse();
			await Assert.That(key.VerifyPreHash(hash, pure, Sha512Oid, context)).IsFalse();
			await Assert.That(key.VerifyMu(Mu(publicKey, message, context), pure)).IsTrue();
			await Assert.That(key.VerifyMu(Mu(publicKey, message), pure)).IsFalse();

			await Assert.That(key.VerifyPreHash(hash, preHash, Sha512Oid, context)).IsTrue();
			await Assert.That(key.VerifyPreHash(hash, preHash, Sha512Oid)).IsFalse();
			await Assert.That(key.VerifyPreHash(hash, preHash, "2.16.840.1.101.3.4.2.10", context)).IsFalse();
			await Assert.That(key.Verify(message, preHash, context)).IsFalse();
			await Assert.That(key.VerifyMu(PreHashMu(publicKey, hash, 3, context), preHash)).IsTrue();

			await Assert.That(key.Verify(message, fromMu, context)).IsTrue();
			await Assert.That(key.VerifyPreHash(hash, fromPreHashMu, Sha512Oid, context)).IsTrue();

			// The SignatureAlgorithm member is ML-DSA with an empty context.
			await Assert.That(key.Verify(message, fromAlgorithm)).IsTrue();
			await Assert.That(key.Verify(AlgorithmsOf<T>()[0], message, Sign(key, message))).IsTrue();
		}
	}

	// Every hash under 2.16.840.1.101.3.4.2 whose collision strength, half its output, reaches λ (FIPS 204, Sec. 5.4), and no other; μ from the reference sponge checks the OID that went into M′.
	[Test]
	public async Task AcceptsExactlyTheHashesOfItsStrength()
	{
		(string Oid, byte Arc, int Length)[] hashes =
		[
			("2.16.840.1.101.3.4.2.1", 1, 32), ("2.16.840.1.101.3.4.2.2", 2, 48), ("2.16.840.1.101.3.4.2.3", 3, 64), ("2.16.840.1.101.3.4.2.4", 4, 28),
			("2.16.840.1.101.3.4.2.5", 5, 28), ("2.16.840.1.101.3.4.2.6", 6, 32), ("2.16.840.1.101.3.4.2.7", 7, 28), ("2.16.840.1.101.3.4.2.8", 8, 32),
			("2.16.840.1.101.3.4.2.9", 9, 48), ("2.16.840.1.101.3.4.2.10", 10, 64), ("2.16.840.1.101.3.4.2.11", 11, 32), ("2.16.840.1.101.3.4.2.12", 12, 64)
		];

		using T key = T.GenerateKey();
		byte[] publicKey = ExportPublicKey(key);
		byte[] context = [7, 7];
		int lambda = Parameters<T>().Lambda;

		using (Assert.Multiple())
		{
			foreach ((string oid, byte arc, int length) in hashes)
			{
				byte[] hash = CreateDeterministicSource(length);
				byte[] signature = new byte[T.SignatureLength];

				if (4 * length < lambda)
				{
					await Assert.That(() => key.SignPreHash(hash, signature, oid, context)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid").Because(oid);
					await Assert.That(() => key.VerifyPreHash(hash, signature, oid, context)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid").Because(oid);
					continue;
				}

				key.SignPreHash(hash, signature, oid, context);
				await Assert.That(key.VerifyPreHash(hash, signature, oid, context)).IsTrue().Because(oid);
				await Assert.That(key.VerifyMu(PreHashMu(publicKey, hash, arc, context), signature)).IsTrue().Because(oid);
				await Assert.That(key.VerifyPreHash(hash, signature, oid)).IsFalse().Because(oid);
			}
		}
	}

	// With a given rnd, signing is deterministic and the same from every instance with the private key.
	[Test]
	public async Task SigningWithAGivenRandomnessIsDeterministic()
	{
		using T generated = T.GenerateKey();
		using T fromPrivateKey = T.ImportPrivateKey(ExportPrivateKey(generated));
		byte[] message = CreateDeterministicSource(20);
		byte[] mu = Mu(ExportPublicKey(generated), message);
		byte[] randomness = CreateDeterministicSource(32);
		byte[] signature = SignWithRandomness(generated, message, [], randomness);

		using (Assert.Multiple())
		{
			await Assert.That(SignWithRandomness(generated, message, [], randomness)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(SignWithRandomness(fromPrivateKey, message, [], randomness)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(SignMuWithRandomness(fromPrivateKey, mu, randomness)).IsEquivalentTo(signature, CollectionOrdering.Matching);
			await Assert.That(SignWithRandomness(generated, message, [], new byte[32])).IsNotEquivalentTo(signature);
		}
	}

	// Every byte of the hints changed, and every hint count pushed past ω.
	[Test]
	public async Task TamperedHintsFailVerification()
	{
		(int k, _, _, _) = Parameters<T>();
		using T key = T.GenerateKey();
		byte[] message = CreateDeterministicSource(30);
		byte[] signature = Sign(key, message);
		int hintOffset = HintStart();
		int omega = T.SignatureLength - hintOffset - k;
		List<string> accepted = [];

		for (int i = hintOffset; i < signature.Length; ++i)
		{
			byte[] tampered = (byte[])signature.Clone();
			++tampered[i];

			if (key.Verify(message, tampered))
			{
				accepted.Add($"byte {i} + 1");
			}

			if (i >= hintOffset + omega)
			{
				tampered[i] = (byte)(omega + 1);

				if (key.Verify(message, tampered))
				{
					accepted.Add($"count {i - hintOffset - omega} past ω");
				}
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(accepted).IsEmpty();
			await Assert.That(key.Verify(message, signature)).IsTrue();
		}
	}

	// The message and μ are read in full before the signature is written over them.
	[Test]
	public async Task SigningMayOverlapItsInput()
	{
		using T key = T.GenerateKey();
		byte[] message = CreateDeterministicSource(T.SignatureLength + 10);
		byte[] mu = Mu(ExportPublicKey(key), message);
		List<int> failures = [];

		foreach (int offset in (int[])[0, 1, 10])
		{
			byte[] buffer = (byte[])message.Clone();
			key.Sign(buffer, buffer.AsSpan(offset, T.SignatureLength));
			byte[] signature = buffer.AsSpan(offset, T.SignatureLength).ToArray();

			byte[] muBuffer = new byte[T.SignatureLength + T.MuLength];
			int muOffset = 100 * offset;
			mu.CopyTo(muBuffer, muOffset);
			key.SignMu(muBuffer.AsSpan(muOffset, T.MuLength), muBuffer.AsSpan(0, T.SignatureLength));
			byte[] muSignature = muBuffer.AsSpan(0, T.SignatureLength).ToArray();

			if (!key.Verify(message, signature) || !key.Verify(message, muSignature))
			{
				failures.Add(offset);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task DisposeErasesTheKey()
	{
		T generated = T.GenerateKey();
		T fromPrivateKey = T.ImportPrivateKey(ExportPrivateKey(generated));
		T fromPublicKey = T.ImportPublicKey(ExportPublicKey(generated));
		byte[] message = CreateDeterministicSource(64);

		// A generated key that has signed and verified fills every field, so the test cannot pass on fields that are always empty.
		await Assert.That(generated.Verify(message, Sign(generated, message))).IsTrue();
		await Assert.That(KeyContents(generated, []).Values).All(static count => count > 0);

		foreach (T key in (T[])[generated, fromPrivateKey, fromPublicKey])
		{
			List<Array> arrays = [];
			Dictionary<string, int> before = KeyContents(key, arrays);
			key.Dispose();
			Dictionary<string, int> after = KeyContents(key, []);

			using (Assert.Multiple())
			{
				await Assert.That(before.Values.Sum()).IsPositive();
				await Assert.That(after.Values).All(static count => count is 0);
				await Assert.That(arrays).IsNotEmpty();
				await Assert.That(arrays).All(static array => IsZero(array));
			}
		}
	}

	// Signing and verification may run concurrently on one instance, including the first of each, which transform the key under a lock.
	[Test]
	public async Task ConcurrentOperationsAgree()
	{
		const int Threads = 8;
		const int Keys = 8;
		const int Calls = 4;
		byte[] seed = CreateDeterministicSource(T.PrivateSeedLength);
		byte[] message = CreateDeterministicSource(64);
		byte[] randomness = new byte[32];
		byte[] expected;

		using (T reference = T.ImportPrivateSeed(seed))
		{
			expected = SignWithRandomness(reference, message, [], randomness);
		}

		int mismatches = 0;

		for (int i = 0; i < Keys; ++i)
		{
			using T key = T.ImportPrivateSeed(seed);
			using Barrier barrier = new(Threads);
			Task<int>[] tasks = new Task<int>[Threads];

			for (int thread = 0; thread < Threads; ++thread)
			{
				// Half the threads verify first, so that the first signature and the first verification race.
				bool verifiesFirst = thread % 2 is 1;
				// Passed as state so that the lambda does not capture disposables.
				tasks[thread] = Task.Factory.StartNew(static state =>
				{
					(T instance, Barrier start, byte[] input, byte[] rnd, byte[] reference, bool verifies) = ((T, Barrier, byte[], byte[], byte[], bool))state!;
					start.SignalAndWait();
					int threadMismatches = 0;

					for (int call = 0; call < Calls; ++call)
					{
						if (verifies && !instance.Verify(input, reference))
						{
							++threadMismatches;
						}

						byte[] hedged = Sign(instance, input);

						if (!SignWithRandomness(instance, input, [], rnd).AsSpan().SequenceEqual(reference) || !instance.Verify(input, hedged))
						{
							++threadMismatches;
						}
					}

					return threadMismatches;
				}, (key, barrier, message, randomness, expected, verifiesFirst), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
			}

			mismatches += (await Task.WhenAll(tasks)).Sum();
		}

		await Assert.That(mismatches).IsZero();
	}

	[Test]
	public async Task KeyOperationsDoNotAllocate()
	{
		// Without optimization, every read of a constant ReadOnlySpan<int>, such as the zetas, allocates a field handle.
		SkipUnlessOptimized<T>();

		using T key = T.GenerateKey();
		Buffers buffers = new(new byte[T.PrivateSeedLength], new byte[T.PrivateKeyLength], new byte[T.PublicKeyLength], new byte[T.SignatureLength], CreateDeterministicSource(100), Mu(ExportPublicKey(key), CreateDeterministicSource(100)), new byte[64]);

		bool valid = Exercise(key, buffers);
		long before = GC.GetAllocatedBytesForCurrentThread();
		valid &= Exercise(key, buffers);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		using (Assert.Multiple())
		{
			await Assert.That(allocated).IsZero();
			await Assert.That(valid).IsTrue();
		}
	}

	// Inputs and outputs that end where an inaccessible page begins must be read and written without faulting.
	[Test]
	public async Task StaysWithinBuffers()
	{
		GuardPageBuffer.SkipUnlessSupported();

		using T generated = T.GenerateKey();
		byte[] seed = ExportPrivateSeed(generated);
		byte[] privateKey = ExportPrivateKey(generated);
		byte[] publicKey = ExportPublicKey(generated);
		byte[] message = CreateDeterministicSource(33);
		byte[] mu = Mu(publicKey, message);
		byte[] hash = SHA512.HashData(message);

		using GuardPageBuffer seedBuffer = new(seed.Length);
		using GuardPageBuffer privateKeyBuffer = new(privateKey.Length);
		using GuardPageBuffer publicKeyBuffer = new(publicKey.Length);
		using GuardPageBuffer messageBuffer = new(message.Length);
		using GuardPageBuffer muBuffer = new(mu.Length);
		using GuardPageBuffer hashBuffer = new(hash.Length);
		using GuardPageBuffer contextBuffer = new(T.MaxContextLength);
		using GuardPageBuffer signatureBuffer = new(T.SignatureLength);
		using GuardPageBuffer muSignatureBuffer = new(T.SignatureLength);
		using GuardPageBuffer preHashSignatureBuffer = new(T.SignatureLength);
		seed.CopyTo(seedBuffer.Span);
		privateKey.CopyTo(privateKeyBuffer.Span);
		publicKey.CopyTo(publicKeyBuffer.Span);
		message.CopyTo(messageBuffer.Span);
		mu.CopyTo(muBuffer.Span);
		hash.CopyTo(hashBuffer.Span);

		using T fromSeed = T.ImportPrivateSeed(seedBuffer.Span);
		using T fromPrivateKey = T.ImportPrivateKey(privateKeyBuffer.Span);
		using T fromPublicKey = T.ImportPublicKey(publicKeyBuffer.Span);

		fromPrivateKey.Sign(messageBuffer.Span, signatureBuffer.Span, contextBuffer.Span);
		fromSeed.SignMu(muBuffer.Span, muSignatureBuffer.Span);
		fromSeed.SignPreHash(hashBuffer.Span, preHashSignatureBuffer.Span, Sha512Oid, contextBuffer.Span);
		bool verified = fromPublicKey.Verify(messageBuffer.Span, signatureBuffer.Span, contextBuffer.Span);
		bool verifiedMu = fromPublicKey.VerifyMu(muBuffer.Span, muSignatureBuffer.Span);
		bool verifiedPreHash = fromPublicKey.VerifyPreHash(hashBuffer.Span, preHashSignatureBuffer.Span, Sha512Oid, contextBuffer.Span);

		fromSeed.ExportPrivateSeed(seedBuffer.Span);
		fromSeed.ExportPrivateKey(privateKeyBuffer.Span);
		fromSeed.ExportPublicKey(publicKeyBuffer.Span);

		using (Assert.Multiple())
		{
			await Assert.That((verified, verifiedMu, verifiedPreHash)).IsEqualTo((true, true, true));
			await Assert.That(seedBuffer.Span.ToArray()).IsEquivalentTo(seed, CollectionOrdering.Matching);
			await Assert.That(privateKeyBuffer.Span.ToArray()).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			await Assert.That(publicKeyBuffer.Span.ToArray()).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}
	}

	private static bool Exercise(T key, Buffers buffers)
	{
		bool valid = true;

		for (int i = 0; i < 2; ++i)
		{
			key.ExportPrivateSeed(buffers.Seed);
			key.ExportPrivateKey(buffers.PrivateKey);
			key.ExportPublicKey(buffers.PublicKey);
			key.Sign(buffers.Message, buffers.Signature);
			valid &= key.Verify(buffers.Message, buffers.Signature);
			key.SignMu(buffers.Mu, buffers.Signature);
			valid &= key.VerifyMu(buffers.Mu, buffers.Signature);
			key.SignPreHash(buffers.Hash, buffers.Signature, Sha512Oid);
			valid &= key.VerifyPreHash(buffers.Hash, buffers.Signature, Sha512Oid);
		}

		return valid;
	}

	// The offset of the hints in a signature: c̃, then l polynomials of z.
	private static int HintStart()
	{
		(_, int l, _, int lambda) = Parameters<T>();
		int zLength = 32 * (lambda is 128 ? 18 : 20);
		return lambda / 4 + l * zLength;
	}

	// The number of nonzero elements or set flags in each field of the key an instance holds; arrays receives the arrays it references.
	private static Dictionary<string, int> KeyContents(T key, List<Array> arrays)
	{
		FieldInfo? keyField = typeof(T).GetField("_key", BindingFlags.Instance | BindingFlags.NonPublic);
		object state = keyField?.GetValue(key) ?? throw new InvalidOperationException($"{typeof(T).Name} has no key field.");
		Dictionary<string, int> contents = [];

		foreach (FieldInfo field in state.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
		{
			switch (field.GetValue(state))
			{
				case int[] polynomials:
				{
					arrays.Add(polynomials);
					contents[field.Name] = polynomials.Length - polynomials.AsSpan().Count(0);
					break;
				}
				case byte[] bytes:
				{
					arrays.Add(bytes);
					contents[field.Name] = bytes.Length - bytes.AsSpan().Count((byte)0);
					break;
				}
				case null:
				{
					contents[field.Name] = 0;
					break;
				}
				case InlineArray64<byte> bytes:
				{
					ReadOnlySpan<byte> span = bytes;
					contents[field.Name] = span.Length - span.Count((byte)0);
					break;
				}
				case InlineArray32<byte> bytes:
				{
					ReadOnlySpan<byte> span = bytes;
					contents[field.Name] = span.Length - span.Count((byte)0);
					break;
				}
				case bool flag:
				{
					contents[field.Name] = flag ? 1 : 0;
					break;
				}
				case Lock:
				{
					break;
				}
				default:
				{
					throw new InvalidOperationException($"The test does not know how to check {field.Name}.");
				}
			}
		}

		return contents;
	}

	private static bool IsZero(Array array)
	{
		return array switch
		{
			int[] ints => !ints.AsSpan().ContainsAnyExcept(0),
			byte[] bytes => !bytes.AsSpan().ContainsAnyExcept((byte)0),
			_ => throw new NotSupportedException(array.GetType().Name)
		};
	}

	// A OneAsymmetricKey (RFC 5958) around an encoded ML-DSA-*-PrivateKey; version 2 with publicKey if given, and with attributes, an encoded [0] field, if given.
	private static byte[] OneAsymmetricKey(byte[] algorithmIdentifier, byte[] privateKey, byte[]? publicKey = null, byte[]? attributes = null, int? version = null)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteInteger(version ?? (publicKey is null ? 0 : 1));
			writer.WriteEncodedValue(algorithmIdentifier);
			writer.WriteOctetString(privateKey);

			if (attributes is not null)
			{
				writer.WriteEncodedValue(attributes);
			}

			if (publicKey is not null)
			{
				writer.WriteBitString(publicKey, 0, new Asn1Tag(TagClass.ContextSpecific, 1));
			}
		}

		return writer.Encode();
	}

	private static byte[] SubjectPublicKeyInfo(byte[] algorithmIdentifier, byte[] publicKey)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(algorithmIdentifier);
			writer.WriteBitString(publicKey);
		}

		return writer.Encode();
	}

	// The three choices of ML-DSA-*-PrivateKey (RFC 9881, Sec. 6).
	private static byte[] SeedChoice(byte[] seed)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteOctetString(seed, new Asn1Tag(TagClass.ContextSpecific, 0));
		return writer.Encode();
	}

	private static byte[] ExpandedKeyChoice(byte[] privateKey)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteOctetString(privateKey);
		return writer.Encode();
	}

	private static byte[] BothChoice(byte[] seed, byte[] privateKey)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteOctetString(seed);
			writer.WriteOctetString(privateKey);
		}

		return writer.Encode();
	}

	private sealed record Buffers(byte[] Seed, byte[] PrivateKey, byte[] PublicKey, byte[] Signature, byte[] Message, byte[] Mu, byte[] Hash);
}

internal class MLDsaTest
{
	// ExpandS squeezes a stream on with its batch when its first two blocks leave it short of 256 coefficients. Each seed, found by search, leaves one stream of ML-DSA-65 short, whose η = 4 rejects enough candidates for that to happen; the reference takes each stream from as many blocks as it needs.
	[Test]
	[Arguments("dde351508bd727157e0810bb8a594f620ab46670b2ca6f14a1fe6dfeaa6edd96", 3)]
	[Arguments("f407c06404e99af47d0c19f3a4db8ccf4d7963a4fc9dc263c2fba3f64ac3ebe3", 6)]
	[Arguments("3a33d0cef9aa04d56310f61dc4dff174d7d7138c04e8686c23433d44d272d65b", 10)]
	public async Task ExpandSContinuesAStreamThatFallsShort(string seedHex, int shortStream)
	{
		const int Rate = 136;
		const int N = MLDsaReference.N;
		(int k, int l, int eta, _) = Parameters<MLDsa65>();
		int etaLength = 32 * MLDsaReference.BitLength(2 * eta);
		byte[] seed = Convert.FromHexString(seedHex);
		byte[] rhoPrime = KeccakReference.Sponge([.. seed, (byte)k, (byte)l], Rate, 0x1F, 128).AsSpan(32, 64).ToArray();

		using MLDsa65 key = MLDsa65.ImportPrivateSeed(seed);
		byte[] privateKey = ExportPrivateKey(key);

		for (int r = 0; r < l + k; ++r)
		{
			byte[] stream = KeccakReference.Sponge([.. rhoPrime, (byte)r, (byte)(r >> 8)], Rate, 0x1F, 4 * Rate);
			bool fallsShort = MLDsaReference.RejectEta(stream.AsSpan(0, 2 * Rate), N, eta).Count < N;
			byte[] expected = MLDsaReference.BitPack([.. MLDsaReference.RejectEta(stream, N, eta)], eta, eta);

			using (Assert.Multiple())
			{
				await Assert.That(fallsShort).IsEqualTo(r == shortStream).Because($"stream {r} of {seedHex}");
				await Assert.That(privateKey.AsSpan(128 + r * etaLength, etaLength).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"stream {r} of {seedHex}");
			}
		}
	}

	// ExpandMask hashes a message in a free lane of its batches where the kernel leaves one. Whatever the lanes, y must be that of Algorithm 34 and the hash SHAKE256 of the message: for messages that end within, at and beyond the blocks the batches permute, for the μ ‖ w1Encode(w1) that signing hashes, and for κ at the start and the end of its range.
	[Test]
	public async Task ExpandMaskHashesAMessageBesideItsStreams()
	{
		await VerifyExpandMask<MLDsa44Parameters>();
		await VerifyExpandMask<MLDsa65Parameters>();
		await VerifyExpandMask<MLDsa87Parameters>();
	}

	private static async Task VerifyExpandMask<TParameters>() where TParameters : struct, IMLDsaParameters
	{
		const int Rate = 136;
		const int N = MLDsaReference.N;
		int l = TParameters.L;
		int gamma1 = 1 << TParameters.Gamma1Bits;
		int zLength = 32 * (TParameters.Gamma1Bits + 1);
		int commitmentLength = 64 + TParameters.K * 32 * (TParameters.Gamma2 == MLDsaConstants.Gamma2Small ? 6 : 4);
		int hashLength = TParameters.Lambda / 4;
		Random random = new(TParameters.K);
		byte[] seed = new byte[64];
		random.NextBytes(seed);

		foreach (int kappa in (int[])[0, 7 * l, ushort.MaxValue + 1 - l])
		{
			int[] expected = new int[l * N];

			for (int r = 0; r < l; ++r)
			{
				int nonce = kappa + r;
				byte[] stream = KeccakReference.Sponge([.. seed, (byte)nonce, (byte)(nonce >> 8)], Rate, 0x1F, zLength);
				MLDsaReference.BitUnpack(stream, gamma1 - 1, gamma1).CopyTo(expected, r * N);
			}

			int[] plain = new int[l * N];
			MLDsaKey<TParameters>.ExpandMask<MLDsaKernelDispatch>(seed, kappa, plain, [], []);
			await Assert.That(plain).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"y without a message at κ = {kappa} with l = {l}");

			foreach (int length in (int[])[1, Rate - 1, Rate, Rate + 1, 5 * Rate - 1, 5 * Rate, 5 * Rate + 1, commitmentLength, 2 * commitmentLength])
			{
				byte[] message = new byte[length];
				random.NextBytes(message);
				int[] y = new int[l * N];
				byte[] hash = new byte[hashLength];
				MLDsaKey<TParameters>.ExpandMask<MLDsaKernelDispatch>(seed, kappa, y, message, hash);

				using (Assert.Multiple())
				{
					await Assert.That(y).IsEquivalentTo(expected, CollectionOrdering.Matching).Because($"y beside a message of {length} bytes at κ = {kappa} with l = {l}");
					await Assert.That(hash).IsEquivalentTo(KeccakReference.Sponge(message, Rate, 0x1F, hashLength), CollectionOrdering.Matching).Because($"the hash of {length} bytes at κ = {kappa} with l = {l}");
				}
			}
		}
	}
}
