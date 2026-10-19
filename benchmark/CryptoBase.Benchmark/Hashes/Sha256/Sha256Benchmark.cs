using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Platform;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha256;

[MemoryDiagnoser]
public class Sha256Benchmark : BclAndBouncyCastleHashBenchmark<Sha256HashAlgorithm, BclSha256, Sha256Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;

	[Benchmark]
	public int Platform()
	{
		return PlatformSha256.HashData(Input, Hash);
	}

	protected override void VerifyAdditionalCompetitors(ReadOnlySpan<byte> expected)
	{
		base.VerifyAdditionalCompetitors(expected);

		Platform();
		Verify(expected, Hash);
	}
}
