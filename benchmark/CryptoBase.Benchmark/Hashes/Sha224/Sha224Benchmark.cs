using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha224;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha224;

[MemoryDiagnoser]
public class Sha224Benchmark : BouncyCastleHashBenchmark<Sha224HashAlgorithm, Sha224Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
