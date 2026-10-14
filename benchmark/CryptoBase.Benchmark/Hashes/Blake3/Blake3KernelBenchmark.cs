using BenchmarkDotNet.Attributes;
using CryptoBase.Hashes.Blake3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Hashes.Blake3;

public class Blake3KernelBenchmark
{
	private readonly byte[] _output = new byte[32 * Blake3Constants.OutLength];
	private byte[] _input = [];

	[Params(1024, 4096, 4095, 8192, 16384, 32768)]
	public int Length { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_input = RandomNumberGenerator.GetBytes(Length);
	}

	[Benchmark(Baseline = true)]
	public void Scalar()
	{
		HashChunks<Blake3Scalar>();
	}

	[Benchmark]
	public void Vector128()
	{
		HashChunks<Blake3Vector128>();
	}

	[Benchmark]
	public void Vector128x2()
	{
		HashChunks<Blake3Vector128x2>();
	}

	[Benchmark]
	public void Vector256()
	{
		HashChunks<Blake3Vector256>();
	}

	[Benchmark]
	public void Vector256Rows()
	{
		HashChunks<Blake3Vector256Rows>();
	}

	[Benchmark]
	public void Vector512()
	{
		HashChunks<Blake3Vector512>();
	}

	[Benchmark]
	public void Vector512x2()
	{
		HashChunks<Blake3Vector512x2>();
	}

	[Benchmark]
	public void Vector512Rows()
	{
		HashChunks<Blake3Vector512Rows>();
	}

	private void HashChunks<TKernel>() where TKernel : IBlake3Kernel
	{
		if (!TKernel.IsSupported)
		{
			throw new PlatformNotSupportedException($"{typeof(TKernel).Name} is not supported in this process.");
		}

		TKernel.HashChunks(ref _input[0], (uint)_input.Length, in Blake3Constants.IV[0], 0, 0, ref _output[0]);
	}
}
