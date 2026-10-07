using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha224;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Hashes.Sha512;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofHmacTest
{
	public static IEnumerable<MacTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<MacTestVector>(fileName);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sha1_test.json"])]
	public Task HmacSha1(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<Sha1HashAlgorithm>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sha224_test.json"])]
	public Task HmacSha224(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<Sha224HashAlgorithm>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sha256_test.json"])]
	public Task HmacSha256(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<Sha256HashAlgorithm>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sha384_test.json"])]
	public Task HmacSha384(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<Sha384HashAlgorithm>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sha512_test.json"])]
	public Task HmacSha512(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<Sha512HashAlgorithm>>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = ["hmac_sm3_test.json"])]
	public Task HmacSM3(MacTestVector vector)
	{
		return Verify<HmacAlgorithm<SM3HashAlgorithm>>(vector);
	}

	private static async Task Verify<TMac>(MacTestVector vector) where TMac : class, IMacAlgorithm<TMac>
	{
		byte[] mac = new byte[TMac.MacLength];
		TMac.Mac(vector.Key, vector.Msg, mac);

		using TMac algorithm = TMac.Create(vector.Key);
		algorithm.Append(vector.Msg);
		byte[] incrementalMac = new byte[TMac.MacLength];
		algorithm.GetMacAndReset(incrementalMac);

		await Assert.That(incrementalMac).IsEquivalentTo(mac, CollectionOrdering.Matching);
		await Assert.That(mac.StartsWith(vector.Tag)).IsEqualTo(vector.Result is WycheproofResult.Valid);
	}
}
