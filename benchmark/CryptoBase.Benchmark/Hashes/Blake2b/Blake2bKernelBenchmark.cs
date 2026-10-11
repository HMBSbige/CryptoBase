using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake2b;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake2b;

public class Blake2bKernelBenchmark
{
	private readonly ulong[] _state = new ulong[8];
	private byte[] _source = [];

	[Params(128, 1024, 8192, 1024 * 1024)]
	public int ByteLength { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_source = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark(Baseline = true)]
	public void Scalar()
	{
		Compress<Blake2bScalar>();
	}

	[Benchmark]
	public void Vector128()
	{
		Compress<Blake2bVector128>();
	}

	[Benchmark]
	public void Vector256()
	{
		Compress<Blake2bVector256>();
	}

	private void Compress<TKernel>() where TKernel : IBlake2bKernel
	{
		if (!TKernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{typeof(TKernel).Name} is not supported in this process.");
		}

		TKernel.Compress(ref _state[0], _source, 128, 0);
	}
}
