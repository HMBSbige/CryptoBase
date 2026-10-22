using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha2;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha2;

[MemoryDiagnoser]
public class Sha512Benchmark : BclAndBouncyCastleHashBenchmark<Sha512Core, BclSha512, Sha512Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block128;
}
