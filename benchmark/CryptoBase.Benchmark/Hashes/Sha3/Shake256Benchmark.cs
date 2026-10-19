using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

[MemoryDiagnoser]
public class Shake256Benchmark : XofBenchmark<Shake256HashAlgorithm, BclShake256, BouncyCastleShake256Digest>
{
	protected override IReadOnlyList<int> AbsorbLengths => HashBenchmarkSizes.Rate136;
}
