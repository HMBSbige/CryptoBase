using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Benchmark.Hashes.Sha3;

public class CShake128Benchmark : CShakeBenchmark<CryptoBaseCShake128, Shake128Core>
{
	protected override IReadOnlyList<int> Sizes => HashBenchmarkSizes.Rate168;
}
