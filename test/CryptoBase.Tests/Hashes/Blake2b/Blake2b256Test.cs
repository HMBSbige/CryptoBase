using CryptoBase.Hashes.Blake2b;
using CryptoBase.Macs.Hmac;
using CryptoBase.Tests.Macs;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake2b;

public class Blake2b256Test
{
	public static IEnumerable<(int Length, string ExpectedHex)> BoundaryVectors =>
	[
		(0, @"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
		(1, @"994ac459b1eb84aac0e76c29d5964d8ca1ec1182a987d0f055981fabd5f11425"),
		(63, @"d9e514666caabb8a01c111d698c84945af71a409c0bbfc06c1b95200059b2690"),
		(64, @"72d3fdccdcfe6f0d03ee967c9e294099f81e293b763c817bcbcac2ab87ed8767"),
		(65, @"b61037221864078bdbef5c223beda080ad5dee197ee0c55d9cc87fc992ea35fe"),
		(127, @"7219ba673cd7dfb22b218032e2a3568656134b53e4ed951427749e1ed4985b3a"),
		(128, @"9697d39ec8789c4878c2726ca69e9c9b3332a3c4ad0d7476cdd6cd02892ce724"),
		(129, @"39b33866d7b10d41cad4aab4de472dc88dfb89f41c9247fd73c43e996f90e70d"),
		(255, @"6ffe67c69c2f0b3b58435b7dfc8d289abad1d5ca021c0751ad5c311aeb3619f9"),
		(256, @"abebbd91f14ecf1d601a9e9be2c2be68c0e1d42ed52fb6c0cf8cad221bfda721"),
		(257, @"e1e3bf0d99babfd28df8da00b476f49a0cd491021a2e44362e726461da7eaf90"),
		(383, @"06fb13b336ff549c96acbf725ed7f2ab413816f329ea723f5a1d93a5bc8397c6"),
		(384, @"3b608be4148ef660677eac5842fbfaff5a0056cf389fd24eb4c6309cb6798f5d"),
		(385, @"1d0693b8c9efcc9a4fa463c7e95fe0e3ff0c5c601a4859842af9426b8536ce1d"),
		(511, @"6a7504c720e6631e5eba706ca378dd9028e8b80165dcb6019f633e36b4831a53"),
		(512, @"617517f1ac4e531da145154332b8289bcd638be8b27cc5a1384bc73b7b76ae27"),
		(513, @"6e9b361116aea722b9a5c6d71af149aea2c3475d9bc95d7fea33f35fa1f75beb"),
		(1023, @"81cb3552450f3542f99888bbd946edf8645166c3a5ef3cfbca8d20790d279425"),
		(1024, @"8ef9079e5e37db0efda6b387a07c4718ce1839e314c0a858d6c183c44379d93b"),
		(1025, @"e6d2a84780cc0a91a8cfc2919fe0dacc281253febaecb5be82746de5ed66392f"),
		(1153, @"3bad45a6e99ebe0a3c89ffb5d3667554f2ed8942f59aa43db7ac1797e91edb44")
	];

	[Test]
	[Arguments("", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")]
	[Arguments("abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")]
	[Arguments("The quick brown fox jumps over the lazy dog", "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Blake2b256HashAlgorithm>(value, expected, 32, 128);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryVectors))]
	public Task BlockBoundaries(int length, string expectedHex)
	{
		return VerifyBoundary<Blake2b256HashAlgorithm>(length, expectedHex);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash128IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Blake2b256HashAlgorithm>(length, sourceOffset, blockSize, static source => GetKnownDigest(source, BoundaryVectors, "BLAKE2b-256"));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Blake2b256HashAlgorithm>(length, offset);
	}

	[Test]
	[Arguments(0, 0, "486b62b89b06365cf96f77c388e093b92aa774ba9eb7530cae6e68a3acbab9e8")]
	[Arguments(32, 3, "c2759e969ed90796fcce469a44815cd4161477e2c30bfbdc46d9df0d7ca1650b")]
	[Arguments(128, 129, "2309c52dabfd62bf4f1cb035baf70f6a03c6b3e8f8b92f97c625cdf8e6ee4c47")]
	[Arguments(129, 200, "602921049edf7f49562fea80598dbd643038075a203ad98dfafd158a8475a187")]
	public Task HmacKnownVectors(int keyLength, int sourceLength, string expectedHex)
	{
		byte[] key = CreateDeterministicSource(keyLength + 1).AsSpan(1).ToArray();
		return MacAlgorithmTestUtils.VerifyVector<HmacAlgorithm<Blake2b256HashAlgorithm>>(key, CreateDeterministicSource(sourceLength), Convert.FromHexString(expectedHex));
	}
}
