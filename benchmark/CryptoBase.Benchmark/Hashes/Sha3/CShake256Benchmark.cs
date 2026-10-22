using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

public class CShake256Benchmark : CShakeBenchmark<CryptoBaseCShake256, Shake256Core>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate136;
}
