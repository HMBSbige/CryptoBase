#pragma warning disable SYSLIB5006

using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Signatures.MLDsa;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.Signatures.MLDsa.MLDsaTestUtils;
using static CryptoBase.Tests.Signatures.SignatureTestUtils;
using BclMLDsa = System.Security.Cryptography.MLDsa;

namespace CryptoBase.Tests.Signatures.MLDsa;

// Differential tests against the platform implementation, where there is one. Not every platform signs or verifies μ itself, so μ is checked through its message methods.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(MLDsa44))]
[GenerateGenericTest(typeof(MLDsa65))]
[GenerateGenericTest(typeof(MLDsa87))]
internal class MLDsaBclTest<T> where T : class, IMLDsa<T>
{
	private const int Iterations = 8;

	// The hashes that the platform knows; it does not know SHA-512/256.
	private static (string Oid, byte Arc, int Length)[] PreHashAlgorithms =>
	[
		("2.16.840.1.101.3.4.2.1", 1, 32), // SHA-256
		("2.16.840.1.101.3.4.2.2", 2, 48), // SHA-384
		("2.16.840.1.101.3.4.2.3", 3, 64), // SHA-512
		("2.16.840.1.101.3.4.2.8", 8, 32), // SHA3-256
		("2.16.840.1.101.3.4.2.9", 9, 48), // SHA3-384
		("2.16.840.1.101.3.4.2.10", 10, 64), // SHA3-512
		("2.16.840.1.101.3.4.2.11", 11, 32), // SHAKE128
		("2.16.840.1.101.3.4.2.12", 12, 64) // SHAKE256
	];

	[Test]
	public async Task SeedsExpandToTheSameKeys()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			byte[] seed = RandomNumberGenerator.GetBytes(T.PrivateSeedLength);
			using T key = T.ImportPrivateSeed(seed);
			using T fromPrivateKey = T.ImportPrivateKey(ExportPrivateKey(key));
			using BclMLDsa bcl = BclMLDsa.ImportMLDsaPrivateSeed(BclAlgorithm<T>(), seed);
			using BclMLDsa bclFromPrivateKey = BclMLDsa.ImportMLDsaPrivateKey(BclAlgorithm<T>(), bcl.ExportMLDsaPrivateKey());

			using (Assert.Multiple())
			{
				await Assert.That(ExportPublicKey(key)).IsEquivalentTo(bcl.ExportMLDsaPublicKey(), CollectionOrdering.Matching);
				await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(bcl.ExportMLDsaPrivateKey(), CollectionOrdering.Matching);
				await Assert.That(ExportSubjectPublicKeyInfo(key)).IsEquivalentTo(bcl.ExportSubjectPublicKeyInfo(), CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(key)).IsEquivalentTo(bcl.ExportPkcs8PrivateKey(), CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(fromPrivateKey)).IsEquivalentTo(bclFromPrivateKey.ExportPkcs8PrivateKey(), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task EachVerifiesWhatTheOtherSigns()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			using T key = T.GenerateKey();
			using BclMLDsa bcl = BclMLDsa.ImportMLDsaPrivateSeed(BclAlgorithm<T>(), ExportPrivateSeed(key));
			byte[] message = RandomNumberGenerator.GetBytes(37 * i);
			byte[] otherContext = [1];

			foreach (byte[] context in Contexts())
			{
				byte[] signature = Sign(key, message, context);
				byte[] bclSignature = bcl.SignData(message, context);

				using (Assert.Multiple())
				{
					await Assert.That(bcl.VerifyData(message, signature, context)).IsTrue();
					await Assert.That(key.Verify(message, bclSignature, context)).IsTrue();
					await Assert.That(bcl.VerifyData(message, signature, otherContext)).IsFalse();
					await Assert.That(key.Verify(message, bclSignature, otherContext)).IsFalse();
				}
			}
		}
	}

	[Test]
	public async Task PreHashSignaturesAgree()
	{
		SkipUnlessSupported();

		using T key = T.GenerateKey();
		using BclMLDsa bcl = BclMLDsa.ImportMLDsaPrivateSeed(BclAlgorithm<T>(), ExportPrivateSeed(key));
		byte[] message = RandomNumberGenerator.GetBytes(100);

		foreach ((string oid, _, int length) in PreHashAlgorithms)
		{
			byte[] hash = RandomNumberGenerator.GetBytes(length);

			// Both refuse a hash weaker than the parameter set.
			if (4 * length < Parameters<T>().Lambda)
			{
				byte[] signature = new byte[T.SignatureLength];

				using (Assert.Multiple())
				{
					await Assert.That(() => key.SignPreHash(hash, signature, oid)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid");
					await Assert.That(() => key.VerifyPreHash(hash, signature, oid)).Throws<ArgumentException>().WithParameterName("hashAlgorithmOid");
					await Assert.That(() => bcl.SignPreHash(hash, oid)).Throws<CryptographicException>();
				}

				continue;
			}

			foreach (byte[] context in Contexts())
			{
				byte[] signature = SignPreHash(key, hash, oid, context);
				byte[] bclSignature = bcl.SignPreHash(hash, oid, context);

				using (Assert.Multiple())
				{
					await Assert.That(bcl.VerifyPreHash(hash, signature, oid, context)).IsTrue().Because(oid);
					await Assert.That(key.VerifyPreHash(hash, bclSignature, oid, context)).IsTrue().Because(oid);
					await Assert.That(key.Verify(message, bclSignature, context)).IsFalse().Because(oid);
				}
			}
		}
	}

	[Test]
	public async Task MuSignaturesAgree()
	{
		SkipUnlessSupported();

		using T key = T.GenerateKey();
		using BclMLDsa bcl = BclMLDsa.ImportMLDsaPrivateSeed(BclAlgorithm<T>(), ExportPrivateSeed(key));
		byte[] publicKey = ExportPublicKey(key);
		byte[] message = RandomNumberGenerator.GetBytes(100);
		(string oid, byte arc, int length) = PreHashAlgorithms.Single(static algorithm => algorithm.Arc is 3);
		byte[] hash = RandomNumberGenerator.GetBytes(length);

		foreach (byte[] context in Contexts())
		{
			byte[] mu = Mu(publicKey, message, context);
			byte[] preHashMu = PreHashMu(publicKey, hash, arc, context);

			using (Assert.Multiple())
			{
				await Assert.That(bcl.VerifyData(message, SignMu(key, mu), context)).IsTrue();
				await Assert.That(key.VerifyMu(mu, bcl.SignData(message, context))).IsTrue();
				await Assert.That(bcl.VerifyPreHash(hash, SignMu(key, preHashMu), oid, context)).IsTrue();
				await Assert.That(key.VerifyMu(preHashMu, bcl.SignPreHash(hash, oid, context))).IsTrue();
			}
		}
	}

	[Test]
	public async Task EachImportsTheKeysOfTheOther()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			using BclMLDsa bcl = BclMLDsa.GenerateKey(BclAlgorithm<T>());
			byte[] privateKey = bcl.ExportMLDsaPrivateKey();
			byte[] publicKey = bcl.ExportMLDsaPublicKey();
			byte[] subjectPublicKeyInfo = bcl.ExportSubjectPublicKeyInfo();
			byte[] pkcs8 = bcl.ExportPkcs8PrivateKey();
			byte[] message = RandomNumberGenerator.GetBytes(i);

			using T fromSeed = T.ImportPrivateSeed(bcl.ExportMLDsaPrivateSeed());
			using T fromPrivateKey = T.ImportPrivateKey(privateKey);
			using T fromPublicKey = T.ImportPublicKey(publicKey);
			using T fromSubjectPublicKeyInfo = T.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
			using T fromPkcs8 = T.ImportPkcs8PrivateKey(pkcs8);
			using T fromExpandedPkcs8 = T.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(fromPrivateKey));
			using BclMLDsa bclFromSubjectPublicKeyInfo = BclMLDsa.ImportSubjectPublicKeyInfo(ExportSubjectPublicKeyInfo(fromPublicKey));
			using BclMLDsa bclFromPkcs8 = BclMLDsa.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(fromPkcs8));
			using BclMLDsa bclFromExpandedPkcs8 = BclMLDsa.ImportPkcs8PrivateKey(ExportPkcs8PrivateKey(fromPrivateKey));
			byte[] bclSignature = bcl.SignData(message);

			using (Assert.Multiple())
			{
				await Assert.That(ExportPrivateKey(fromSeed)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				await Assert.That(ExportPublicKey(fromPrivateKey)).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
				await Assert.That(ExportPkcs8PrivateKey(fromPkcs8)).IsEquivalentTo(pkcs8, CollectionOrdering.Matching);
				await Assert.That(ExportPrivateKey(fromExpandedPkcs8)).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
				await Assert.That(fromSubjectPublicKeyInfo.Verify(message, bclSignature)).IsTrue();
				await Assert.That(bclFromSubjectPublicKeyInfo.VerifyData(message, Sign(fromPrivateKey, message))).IsTrue();
				await Assert.That(bcl.VerifyData(message, Sign(fromPkcs8, message))).IsTrue();
				await Assert.That(bclFromPkcs8.ExportMLDsaPrivateSeed()).IsEquivalentTo(bcl.ExportMLDsaPrivateSeed(), CollectionOrdering.Matching);
				await Assert.That(bclFromExpandedPkcs8.ExportMLDsaPrivateKey()).IsEquivalentTo(privateKey, CollectionOrdering.Matching);
			}
		}
	}

	private static IEnumerable<byte[]> Contexts()
	{
		yield return [];
		yield return RandomNumberGenerator.GetBytes(7);
		yield return RandomNumberGenerator.GetBytes(255);
	}
}

internal class MLDsaBclTest
{
	// ExpandS squeezes more than two SHAKE256 blocks for a polynomial only for η = 4, and rarely, so a seed is searched for that needs them in some polynomial of s1 or s2.
	[Test]
	public async Task SecretsThatNeedMoreBlocksMatchThePlatform()
	{
		SkipUnlessSupported();

		byte[] seed = SeedNeedingMoreSecretBlocks(6, 5);
		using MLDsa65 key = MLDsa65.ImportPrivateSeed(seed);
		using BclMLDsa bcl = BclMLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, seed);
		await Assert.That(ExportPrivateKey(key)).IsEquivalentTo(bcl.ExportMLDsaPrivateKey(), CollectionOrdering.Matching);
	}

	// The first of the seeds ξ = 0, 1, 2, ... (little-endian) for which two SHAKE256 blocks of some stream of ExpandS hold fewer than 256 coefficients in [−4, 4], with η = 4.
	private static byte[] SeedNeedingMoreSecretBlocks(int k, int l)
	{
		byte[] expanded = new byte[128];
		byte[] blocks = new byte[2 * 136];

		for (int counter = 0; counter < 1_000_000; ++counter)
		{
			byte[] seed = new byte[32];
			BinaryPrimitives.WriteInt32LittleEndian(seed, counter);
			Xof<Shake256Core>.HashData([.. seed, (byte)k, (byte)l], expanded);

			for (int nonce = 0; nonce < k + l; ++nonce)
			{
				Xof<Shake256Core>.HashData([.. expanded.AsSpan(32, 64), (byte)nonce, 0], blocks);
				int accepted = blocks.Sum(static b => (b & 15) < 9 ? 1 : 0) + blocks.Sum(static b => b >> 4 < 9 ? 1 : 0);

				if (accepted < 256)
				{
					return seed;
				}
			}
		}

		throw new InvalidOperationException("No seed found that needs more blocks.");
	}
}
