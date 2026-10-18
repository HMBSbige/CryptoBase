using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// .NET has no SHA3-224.
[MemoryDiagnoser]
public class Sha3_224Benchmark : BouncyCastleHashBenchmark<Sha3_224HashAlgorithm, BouncyCastleSha3_224Digest>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate144;
}
