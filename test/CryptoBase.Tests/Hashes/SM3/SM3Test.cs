using CryptoBase.Hashes.SM3;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.SM3;

public class SM3Test
{
	public static IEnumerable<(int Length, string ExpectedHex)> BoundaryVectors =>
	[
		(0, @"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
		(1, @"15af394b36686ef558aa13ee5946f0f5c8b0084801ace780eb6eb301f068972e"),
		(54, @"1eb046aa938775203bd08e18a54c6d665d81317bacb57e84179ad967a1546bce"),
		(55, @"8704f164a9e1897880749079079a65250ca2bef68c6daff4e7f79da2d4ee526b"),
		(56, @"2b0c45fd2212784c2c7e9e73cd5582e42f403a3e4f1b2a2307700601dabee147"),
		(63, @"6f2c256511c9dff2e33a7dad3ea968e2aab67fa0f00fc274ee842e42be4ebaa0"),
		(64, @"c1eb75cc6213883a9ec74073404e92b17dfca7f432f3bfd1313d53a2a8f339ca"),
		(65, @"344b448491308db3738b3806a812f89702bb0a00fde37e1ab789e3af0dd88beb"),
		(118, @"4dc4da51d8b7379997b4687ac388943153d342ec51b092a82af0a830c20854b2"),
		(119, @"7ab4bc65ee44fdd1d0926eeb41907a55e34e90e89e33c3accb154bb98a6a4976"),
		(120, @"26891eec21d797e1fd0f3801935cce07704053d4a1b96e532d13b1fdf78fe2a1"),
		(127, @"9520e6874816ad1b964ff8d4fd0ab0f7950b0b875bdf8b003f954b11a047cd13"),
		(128, @"bac7c850aefac3f2593ab6a9cfabf93f4abb55635112274345f81cf8f3098297"),
		(129, @"e902c4d32e2e7cc2175cb9c343e98c49d0dd9980e47282ca6a6567d273848c53"),
		(255, @"476f2514bc2f35a8fe98a1f987daa6f2b834d4e0c11d66a268065a1b1373d46a"),
		(256, @"debb1c4ea8dd6025a7eea58b6160b61addcafc188f3a2b665a90d5d4410cb056"),
		(257, @"a5449c09a5f180e88d6898a2d3058b7e7358cf57055254830fe543fb4678adea"),
		(511, @"33ad92533fbb16771839fbf14519ebaa53628f31fcdfca524b7b6b3db8fb6a57"),
		(512, @"5fd00b7075b93b39c1ea3ea21632fa5339b9f4c224af3a773bc7debcf67916f8"),
		(513, @"e996aaa47ed116f2618cf005df6337ffda211cb78eac4f562c6e3582be9652b6"),
		(1023, @"19f435f430b62b29800ab10c5e5acda02516f7cb85c254f5de4dc7cf74d3d232"),
		(1024, @"ffda7088e6ae13884b7848c69989bf18abe730edcc0b854ac8db480c9134e612"),
		(1025, @"35dcdb40a448e6407b3d225bc96ad19b648a551258bff7299673d47e72007e46"),
		(1089, @"6e1dcf3c67b20959cf7507a2ad91929d6eeafab15d95029549ae5a64cb04392a")
	];

	[Test]
	[Arguments("", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")]
	[Arguments("abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")]
	[Arguments("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<SM3HashAlgorithm>(value, expected, 32, 64);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryVectors))]
	public Task BlockBoundaries(int length, string expectedHex)
	{
		return VerifyBoundary<SM3HashAlgorithm>(length, expectedHex);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<SM3HashAlgorithm>(length, sourceOffset, blockSize, static source => GetKnownDigest(source, BoundaryVectors, "SM3"));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<SM3HashAlgorithm>(length, offset);
	}
}
