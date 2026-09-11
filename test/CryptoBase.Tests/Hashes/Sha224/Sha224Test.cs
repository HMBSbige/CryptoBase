using CryptoBase.Hashes.Sha224;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;

namespace CryptoBase.Tests.Hashes.Sha224;

public class Sha224Test
{
	public static IEnumerable<(int Length, string ExpectedHex)> BoundaryVectors =>
	[
		(0, @"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
		(1, @"f603870ae2a797c8600b7a96429276404a400f0ddc229ee6e8eb4ca0"),
		(54, @"eba5b2443ce869f9d4ba201f9d1b0f2dcd0a02d73932dc521b1ca6a2"),
		(55, @"263a81dccb827d1c869031950e889c2c8406b692035dedd4b87a5e5b"),
		(56, @"c68cbdb46b95420ed0bab3974921fb33e01093c351cda7edd43812e2"),
		(63, @"f7ff5fad4a55e0210275a9440dc9b0a9d9ed04f7be86a17e4558afdd"),
		(64, @"82ed4c5dbb368521c1628d7da8ba141694972178e3a29218d7fa11dd"),
		(65, @"96d1452940232bc730de23d21415a2ef8ab0a54c409d1b27399c6a74"),
		(118, @"fd82d5d7ef6a06d5eeca2fcceed70746917ecec411164ed7a5823fb2"),
		(119, @"76a0ff74bd5ed6576e50d34d8b63388bf46750acd503751baafbbf0d"),
		(120, @"c42c273db995a5b2a94620e3956141c017555822b98eabd0a5898104"),
		(127, @"7ad6b99daeac34a893659e3b9ad9d45d1880bb68e4e74320a925076f"),
		(128, @"0be45f4f59bd8c7b3827fda37b3d5a433ba732837f7e7a8fb80008bf"),
		(129, @"db215409ab710b00b16ed9acacf1467302f61238d7d186f2ce49d252"),
		(255, @"505cfd85a5c5bddf2be8958de94cfa29995df5bd91427b3dc58e6629"),
		(256, @"c00d3c5db00c21dde1ae14cc50a8a69095f5fdc0f74f5cdcdcf52f59"),
		(257, @"4385b20658e2bcc6a657cb75de6cf6d7a0aee0f41f5932041f438c28"),
		(511, @"cefad661dc3a2a661891257f875dee439cc10503a8a8a185fc6c7b6b"),
		(512, @"2e19f36cd09a2473ed16c66c923ea007b1674220ff71cf833c3a1f4e"),
		(513, @"9da68b5609adfc78673a2d30ee53040ffd8f5eabb4bf6a9e181db35c"),
		(1023, @"9d9a2a6c19bbcfc26d61f926339bc3aab53aa045793c28ba46202118"),
		(1024, @"631722ab207d4409d73980e8156a989a17aebe0e309d2e4c9a77342b"),
		(1025, @"6d2576b29c3724fb6c255d5240b0cf90fa68a52043937c6747d6fede"),
		(1089, @"f78bf04929a490d79e7194297f24c52d3e77cbaf81bb4abbee83c3e4")
	];

	[Test]
	[Arguments(@"abc", @"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")]
	[Arguments(@"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", @"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")]
	[Arguments(@"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", @"c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Sha224HashAlgorithm>(value, expected, 28, 64);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryVectors))]
	public Task BlockBoundaries(int length, string expectedHex)
	{
		return VerifyBoundary<Sha224HashAlgorithm>(length, expectedHex);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash64IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Sha224HashAlgorithm>(length, sourceOffset, blockSize, static source => GetKnownDigest(source, BoundaryVectors, "SHA-224"));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Sha224HashAlgorithm>(length, offset);
	}
}
