using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

[MemoryDiagnoser]
public class Sha3_512Benchmark : BclAndBouncyCastleHashBenchmark<Sha3_512HashAlgorithm, BclSha3_512, BouncyCastleSha3_512Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate72;
}
