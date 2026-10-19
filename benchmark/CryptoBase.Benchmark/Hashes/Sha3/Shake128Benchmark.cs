using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

[MemoryDiagnoser]
public class Shake128Benchmark : XofBenchmark<Shake128HashAlgorithm, BclShake128, BouncyCastleShake128Digest>
{
	protected override IReadOnlyList<int> AbsorbLengths => HashBenchmarkSizes.Rate168;
}
