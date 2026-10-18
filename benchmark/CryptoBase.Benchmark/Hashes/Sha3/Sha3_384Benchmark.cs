using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

[MemoryDiagnoser]
public class Sha3_384Benchmark : BclAndBouncyCastleHashBenchmark<Sha3_384HashAlgorithm, BclSha3_384, BouncyCastleSha3_384Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate104;
}
