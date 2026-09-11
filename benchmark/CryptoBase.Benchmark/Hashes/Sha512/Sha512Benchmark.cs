using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha512;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha512;

[MemoryDiagnoser]
public class Sha512Benchmark : BclAndBouncyCastleHashBenchmark<Sha512HashAlgorithm, BclSha512, Sha512Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block128;
}
