using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha1;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha1;

[MemoryDiagnoser]
public class Sha1Benchmark : BclAndBouncyCastleHashBenchmark<Sha1HashAlgorithm, BclSha1, Sha1Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
