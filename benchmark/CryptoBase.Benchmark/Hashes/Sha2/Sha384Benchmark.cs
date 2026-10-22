using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha2;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha2;

[MemoryDiagnoser]
public class Sha384Benchmark : BclAndBouncyCastleHashBenchmark<Sha384Core, BclSha384, Sha384Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block128;
}
