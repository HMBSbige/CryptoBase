using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Internal;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// The interleaved kernels count one operation per state, so their times are per state permuted and compare directly with Scalar.
public class KeccakP1600Benchmark
{
	private readonly ulong[] _states = new ulong[25 * KeccakP1600Times8.Lanes];
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

	[Benchmark(OperationsPerInvoke = 2)]
	public void Times2()
	{
		Permute<KeccakP1600Times2>();
	}

	[Benchmark(OperationsPerInvoke = 4)]
	public void Times4()
	{
		Permute<KeccakP1600Times4>();
	}

	[Benchmark(OperationsPerInvoke = 8)]
	public void Times8()
	{
		Permute<KeccakP1600Times8>();
	}

	private void Permute<TKernel>() where TKernel : IKeccakP1600Kernel
	{
		if (!TKernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{typeof(TKernel).Name} is not supported in this process.");
		}

		TKernel.Permute(ref _states[0]);
	}
}
