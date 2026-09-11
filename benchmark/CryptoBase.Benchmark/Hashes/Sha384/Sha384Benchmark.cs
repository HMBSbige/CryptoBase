using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha384;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha384;

[MemoryDiagnoser]
public class Sha384Benchmark : BclAndBouncyCastleHashBenchmark<Sha384HashAlgorithm, BclSha384, Sha384Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block128;
}
