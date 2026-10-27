using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;
using System.Security.Cryptography;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.Kems.MLKem.MLKemTestUtils;
using BclMLKem = System.Security.Cryptography.MLKem;

namespace CryptoBase.Tests.Kems.MLKem;

// Differential tests against the platform implementation, where there is one.
[GenerateGenericTest(typeof(MLKem512))]
[GenerateGenericTest(typeof(MLKem768))]
[GenerateGenericTest(typeof(MLKem1024))]
public class MLKemBclTest<T> where T : class, IKem<T>
{
	private const int Iterations = 8;

	[Test]
	public async Task SeedsExpandToTheSameKeys()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			byte[] seed = RandomNumberGenerator.GetBytes(T.PrivateSeedLength);
			using T kem = T.ImportPrivateSeed(seed);
			using BclMLKem bcl = BclMLKem.ImportPrivateSeed(BclAlgorithm<T>(), seed);

			using (Assert.Multiple())
			{
				await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(bcl.ExportEncapsulationKey(), CollectionOrdering.Matching);
				await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(bcl.ExportDecapsulationKey(), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task EachDecapsulatesWhatTheOtherEncapsulates()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			using T kem = T.GenerateKey();
			using BclMLKem bcl = BclMLKem.ImportPrivateSeed(BclAlgorithm<T>(), ExportPrivateSeed(kem));

			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem);
			bcl.Encapsulate(out byte[] bclCiphertext, out byte[] bclSharedSecret);

			using (Assert.Multiple())
			{
				await Assert.That(bcl.Decapsulate(ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(kem, bclCiphertext)).IsEquivalentTo(bclSharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	public async Task ImportsPlatformGeneratedKeys()
	{
		SkipUnlessSupported();

		for (int i = 0; i < Iterations; ++i)
		{
			using BclMLKem bcl = BclMLKem.GenerateKey(BclAlgorithm<T>());
			byte[] seed = bcl.ExportPrivateSeed();
			byte[] decapsulationKey = bcl.ExportDecapsulationKey();
			byte[] encapsulationKey = bcl.ExportEncapsulationKey();

			using T fromSeed = T.ImportPrivateSeed(seed);
			using T fromDecapsulationKey = T.ImportDecapsulationKey(decapsulationKey);
			using T fromEncapsulationKey = T.ImportEncapsulationKey(encapsulationKey);
			(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(fromEncapsulationKey);
			bcl.Encapsulate(out byte[] bclCiphertext, out byte[] bclSharedSecret);

			using (Assert.Multiple())
			{
				await Assert.That(ExportDecapsulationKey(fromSeed)).IsEquivalentTo(decapsulationKey, CollectionOrdering.Matching);
				await Assert.That(ExportEncapsulationKey(fromDecapsulationKey)).IsEquivalentTo(encapsulationKey, CollectionOrdering.Matching);
				await Assert.That(bcl.Decapsulate(ciphertext)).IsEquivalentTo(sharedSecret, CollectionOrdering.Matching);
				await Assert.That(Decapsulate(fromDecapsulationKey, bclCiphertext)).IsEquivalentTo(bclSharedSecret, CollectionOrdering.Matching);
			}
		}
	}

	private static void SkipUnlessSupported()
	{
		if (!BclMLKem.IsSupported)
		{
			Skip.Test("The platform does not support ML-KEM.");
		}
	}
}
