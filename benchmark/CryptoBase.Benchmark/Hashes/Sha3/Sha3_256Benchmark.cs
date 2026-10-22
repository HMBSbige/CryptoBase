using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha3;

[MemoryDiagnoser]
public class Sha3_256Benchmark : BclAndBouncyCastleHashBenchmark<Sha3_256Core, BclSha3_256, Sha3Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate136;
}
