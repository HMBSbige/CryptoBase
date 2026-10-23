using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;
using static CryptoBase.Tests.Kems.KemTestUtils;
using static CryptoBase.Tests.Kems.MLKem.MLKemTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofMLKemTest
{
	public static IEnumerable<MLKemTestVector> DecapsulationVectors(string fileName)
	{
		return WycheproofVectors.Load<MLKemTestVector>(fileName);
	}

	public static IEnumerable<MLKemEncapsTestVector> EncapsulationVectors(string fileName)
	{
		return WycheproofVectors.Load<MLKemEncapsTestVector>(fileName);
	}

	public static IEnumerable<MLKemKeyGenTestVector> KeyGenerationVectors(string fileName)
	{
		return WycheproofVectors.Load<MLKemKeyGenTestVector>(fileName);
	}

	public static IEnumerable<MLKemDecapsValidationTestVector> DecapsulationKeyVectors(string fileName)
	{
		return WycheproofVectors.Load<MLKemDecapsValidationTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationVectors), Arguments = ["mlkem_512_test.json"])]
	public Task Decapsulation512(MLKemTestVector vector)
	{
		return VerifyDecapsulation<MLKem512>(vector);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationVectors), Arguments = ["mlkem_768_test.json"])]
	public Task Decapsulation768(MLKemTestVector vector)
	{
		return VerifyDecapsulation<MLKem768>(vector);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationVectors), Arguments = ["mlkem_1024_test.json"])]
	public Task Decapsulation1024(MLKemTestVector vector)
	{
		return VerifyDecapsulation<MLKem1024>(vector);
	}

	[Test]
	[MethodDataSource(nameof(EncapsulationVectors), Arguments = ["mlkem_512_encaps_test.json"])]
	public Task Encapsulation512(MLKemEncapsTestVector vector)
	{
		return VerifyEncapsulation<MLKem512>(vector);
	}

	[Test]
	[MethodDataSource(nameof(EncapsulationVectors), Arguments = ["mlkem_768_encaps_test.json"])]
	public Task Encapsulation768(MLKemEncapsTestVector vector)
	{
		return VerifyEncapsulation<MLKem768>(vector);
	}

	[Test]
	[MethodDataSource(nameof(EncapsulationVectors), Arguments = ["mlkem_1024_encaps_test.json"])]
	public Task Encapsulation1024(MLKemEncapsTestVector vector)
	{
		return VerifyEncapsulation<MLKem1024>(vector);
	}

	[Test]
	[MethodDataSource(nameof(KeyGenerationVectors), Arguments = ["mlkem_512_keygen_seed_test.json"])]
	public Task KeyGeneration512(MLKemKeyGenTestVector vector)
	{
		return VerifyKeyGeneration<MLKem512>(vector);
	}

	[Test]
	[MethodDataSource(nameof(KeyGenerationVectors), Arguments = ["mlkem_768_keygen_seed_test.json"])]
	public Task KeyGeneration768(MLKemKeyGenTestVector vector)
	{
		return VerifyKeyGeneration<MLKem768>(vector);
	}

	[Test]
	[MethodDataSource(nameof(KeyGenerationVectors), Arguments = ["mlkem_1024_keygen_seed_test.json"])]
	public Task KeyGeneration1024(MLKemKeyGenTestVector vector)
	{
		return VerifyKeyGeneration<MLKem1024>(vector);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationKeyVectors), Arguments = ["mlkem_512_semi_expanded_decaps_test.json"])]
	public Task DecapsulationKey512(MLKemDecapsValidationTestVector vector)
	{
		return VerifyDecapsulationKey<MLKem512>(vector);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationKeyVectors), Arguments = ["mlkem_768_semi_expanded_decaps_test.json"])]
	public Task DecapsulationKey768(MLKemDecapsValidationTestVector vector)
	{
		return VerifyDecapsulationKey<MLKem768>(vector);
	}

	[Test]
	[MethodDataSource(nameof(DecapsulationKeyVectors), Arguments = ["mlkem_1024_semi_expanded_decaps_test.json"])]
	public Task DecapsulationKey1024(MLKemDecapsValidationTestVector vector)
	{
		return VerifyDecapsulationKey<MLKem1024>(vector);
	}

	// The invalid vectors have a seed or a ciphertext of the wrong length; the valid ones include ciphertexts that
	// decapsulation must reject implicitly.
	private static async Task VerifyDecapsulation<T>(MLKemTestVector vector) where T : class, IKem<T>
	{
		if (vector.Seed.Length != T.PrivateSeedLength)
		{
			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => T.ImportPrivateSeed(vector.Seed)).Throws<ArgumentException>();
			}

			return;
		}

		using T kem = T.ImportPrivateSeed(vector.Seed);

		if (vector.Ek is not null)
		{
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(vector.Ek, CollectionOrdering.Matching);
		}

		if (vector.Result is WycheproofResult.Invalid)
		{
			(bool result, byte[] output) = TryDecapsulate(kem, vector.C);

			using (Assert.Multiple())
			{
				await Assert.That(vector.C.Length).IsNotEqualTo(T.CiphertextLength);
				await Assert.That(result).IsFalse();
				await Assert.That(output).All(static value => value is DestinationSentinel);
			}

			return;
		}

		await Assert.That(Decapsulate(kem, vector.C)).IsEquivalentTo(vector.K, CollectionOrdering.Matching);
	}

	// The invalid vectors have an encapsulation key of the wrong length or with a coefficient of q or more.
	private static async Task VerifyEncapsulation<T>(MLKemEncapsTestVector vector) where T : class, IKem<T>
	{
		if (vector.Result is WycheproofResult.Invalid)
		{
			await Assert.That(() => T.ImportEncapsulationKey(vector.Ek)).Throws<ArgumentException>();
			return;
		}

		using T kem = T.ImportEncapsulationKey(vector.Ek);
		(byte[] ciphertext, byte[] sharedSecret) = Encapsulate(kem, vector.M);

		using (Assert.Multiple())
		{
			await Assert.That(ciphertext).IsEquivalentTo(vector.C, CollectionOrdering.Matching);
			await Assert.That(sharedSecret).IsEquivalentTo(vector.K, CollectionOrdering.Matching);
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(vector.Ek, CollectionOrdering.Matching);
		}
	}

	private static async Task VerifyKeyGeneration<T>(MLKemKeyGenTestVector vector) where T : class, IKem<T>
	{
		await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Valid);

		using T kem = T.ImportPrivateSeed(vector.Seed);
		using T imported = T.ImportDecapsulationKey(vector.Dk);

		using (Assert.Multiple())
		{
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(vector.Ek, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(vector.Dk, CollectionOrdering.Matching);
			await Assert.That(ExportPrivateSeed(kem)).IsEquivalentTo(vector.Seed, CollectionOrdering.Matching);
			await Assert.That(ExportEncapsulationKey(imported)).IsEquivalentTo(vector.Ek, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(imported)).IsEquivalentTo(vector.Dk, CollectionOrdering.Matching);
		}
	}

	// The invalid vectors have a ciphertext or a decapsulation key of the wrong length, or a decapsulation key whose hash or embedded
	// encapsulation key was corrupted.
	private static async Task VerifyDecapsulationKey<T>(MLKemDecapsValidationTestVector vector) where T : class, IKem<T>
	{
		if (vector.Flags.Contains("IncorrectCiphertextLength"))
		{
			using T valid = T.ImportDecapsulationKey(vector.Dk);
			(bool result, byte[] output) = TryDecapsulate(valid, vector.C);

			using (Assert.Multiple())
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(vector.C.Length).IsNotEqualTo(T.CiphertextLength);
				await Assert.That(result).IsFalse();
				await Assert.That(output).All(static value => value is DestinationSentinel);
			}

			return;
		}

		if (vector.Result is WycheproofResult.Invalid)
		{
			await Assert.That(() => T.ImportDecapsulationKey(vector.Dk)).Throws<ArgumentException>();
			return;
		}

		byte[] expected = vector.K ?? throw new InvalidOperationException("A valid vector has a shared secret.");
		using T kem = T.ImportDecapsulationKey(vector.Dk);

		using (Assert.Multiple())
		{
			await Assert.That(ExportEncapsulationKey(kem)).IsEquivalentTo(vector.Ek, CollectionOrdering.Matching);
			await Assert.That(ExportDecapsulationKey(kem)).IsEquivalentTo(vector.Dk, CollectionOrdering.Matching);
			await Assert.That(Decapsulate(kem, vector.C)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}
}
