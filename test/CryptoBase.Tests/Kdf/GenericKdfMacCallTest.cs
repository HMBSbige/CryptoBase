using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using static CryptoBase.Tests.Kdf.KdfTestUtils;

namespace CryptoBase.Tests.Kdf;

public class GenericKdfMacCallTest
{
	private const int MacLength = 32;

	[Test]
	[Arguments(1)]
	[Arguments(31)]
	[Arguments(32)]
	public Task HkdfUsesOneShotMacForOneBlock(int outputLength)
	{
		return VerifyHkdf(outputLength, new MacCallCounts { Mac = 1 }, new MacCallCounts { Mac = 2 });
	}

	[Test]
	[Arguments(33, 2)]
	[Arguments(64, 2)]
	[Arguments(65, 3)]
	[Arguments(255 * MacLength, 255)]
	public Task HkdfReusesOneKeyedMacForMoreBlocks(int outputLength, int blockCount)
	{
		MacCallCounts keyed = new() { Create = 1, Append = blockCount, GetMacAndReset = blockCount, Dispose = 1 };
		return VerifyHkdf(outputLength, keyed, keyed with { Mac = 1 });
	}

	[Test]
	[Arguments(1)]
	[Arguments(31)]
	[Arguments(32)]
	public Task Tls12PrfUsesOneShotMacForOneBlock(int outputLength)
	{
		// A(1) and the block.
		return VerifyTls12Prf(outputLength, new MacCallCounts { Mac = 2 });
	}

	[Test]
	[Arguments(33, 2)]
	[Arguments(48, 2)]
	[Arguments(64, 2)]
	[Arguments(65, 3)]
	[Arguments(256 * MacLength + 7, 257)]
	public Task Tls12PrfReusesOneKeyedMacForMoreBlocks(int outputLength, int blockCount)
	{
		// A(1) to A(n) and the n blocks.
		int macCount = 2 * blockCount;
		return VerifyTls12Prf(outputLength, new MacCallCounts { Create = 1, Append = macCount, GetMacAndReset = macCount, Dispose = 1 });
	}

	private static async Task VerifyHkdf(int outputLength, MacCallCounts expandCalls, MacCallCounts deriveKeyCalls)
	{
		byte[] ikm = CreateData(73, 11);
		byte[] salt = CreateData(37, 29);
		byte[] info = CreateData(23, 47);
		byte[] prk = CreateData(MacLength, 13);
		byte[] expected = new byte[outputLength];
		byte[] actual = new byte[outputLength];

		MacCallCounts counts = RecordingHmacSha256.Record();
		Hkdf<RecordingHmacSha256>.Expand(prk, actual, info);
		await Assert.That(counts).IsEqualTo(expandCalls);
		Hkdf.Expand<Sha256Core>(prk, expected, info);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

		counts = RecordingHmacSha256.Record();
		Hkdf<RecordingHmacSha256>.DeriveKey(ikm, actual, salt, info);
		await Assert.That(counts).IsEqualTo(deriveKeyCalls);
		Hkdf.DeriveKey<Sha256Core>(ikm, expected, salt, info);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	private static async Task VerifyTls12Prf(int outputLength, MacCallCounts calls)
	{
		byte[] secret = CreateData(48, 3);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed = CreateData(64, 5);
		byte[] expected = new byte[outputLength];
		byte[] actual = new byte[outputLength];

		MacCallCounts counts = RecordingHmacSha256.Record();
		Tls12Prf<RecordingHmacSha256>.DeriveKey(secret, label, seed, actual);
		await Assert.That(counts).IsEqualTo(calls);
		Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed, expected);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
