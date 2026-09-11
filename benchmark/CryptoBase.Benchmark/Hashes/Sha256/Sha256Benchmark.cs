using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha256;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha256;

[MemoryDiagnoser]
public class Sha256Benchmark : BclAndBouncyCastleHashBenchmark<Sha256HashAlgorithm, BclSha256, Sha256Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
