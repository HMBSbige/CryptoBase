using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofHkdfTest
{
	public static IEnumerable<HkdfTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<HkdfTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hkdf_sha1_test.json"])]
	public Task HkdfSha1(HkdfTestVector vector)
	{
		return Verify<Sha1Core>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hkdf_sha256_test.json"])]
	public Task HkdfSha256(HkdfTestVector vector)
	{
		return Verify<Sha256Core>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hkdf_sha384_test.json"])]
	public Task HkdfSha384(HkdfTestVector vector)
	{
		return Verify<Sha384Core>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hkdf_sha512_test.json"])]
	public Task HkdfSha512(HkdfTestVector vector)
	{
		return Verify<Sha512Core>(vector);
	}

	private static async Task Verify<TCore>(HkdfTestVector vector) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		byte[] prk = new byte[TCore.HashLength];
		Hkdf.Extract<TCore>(vector.Ikm, vector.Salt, prk);
		byte[] expanded = new byte[vector.Size];
		byte[] derived = new byte[vector.Size];

		if (vector.Result is WycheproofResult.Invalid)
		{
			// The invalid vectors request more than 255 output blocks.
			await Assert.That(() => Hkdf.Expand<TCore>(prk, expanded, vector.Info)).Throws<ArgumentException>();
			await Assert.That(() => Hkdf.DeriveKey<TCore>(vector.Ikm, derived, vector.Salt, vector.Info)).Throws<ArgumentException>();
			return;
		}

		Hkdf.Expand<TCore>(prk, expanded, vector.Info);
		Hkdf.DeriveKey<TCore>(vector.Ikm, derived, vector.Salt, vector.Info);
		await Assert.That(expanded).IsEquivalentTo(vector.Okm, CollectionOrdering.Matching);
		await Assert.That(derived).IsEquivalentTo(vector.Okm, CollectionOrdering.Matching);
	}
}
