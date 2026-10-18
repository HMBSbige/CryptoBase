using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;

namespace CryptoBase.Benchmark.Hashes.Sha3;

public class KeccakP1600Benchmark
{
	private InlineArray25<ulong> _state;

	[Benchmark(Baseline = true)]
	public void Scalar()
	{
		KeccakP1600.PermuteScalar(ref _state);
	}

	[Benchmark]
	public void Permute()
	{
		KeccakP1600.Permute(ref _state);
	}
}
