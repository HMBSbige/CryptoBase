using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha2;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha2;

[MemoryDiagnoser]
public class Sha224Benchmark : BouncyCastleHashBenchmark<Sha224HashAlgorithm, Sha224Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
