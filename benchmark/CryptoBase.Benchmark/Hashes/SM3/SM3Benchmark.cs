using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.SM3;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.SM3;

[MemoryDiagnoser]
public class SM3Benchmark : BouncyCastleHashBenchmark<SM3HashAlgorithm, SM3Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Block64;
}
