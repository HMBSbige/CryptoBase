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
		Blake2bScalar.Compress(ref _state[0], _source, 128, 0);
	}

	[Benchmark]
	public void Vector128()
	{
		if (Blake2bVector128.IsSupported)
		{
			Blake2bVector128.Compress(ref _state[0], _source, 128, 0);
		}
	}

	[Benchmark]
	public void Vector256()
	{
		if (Blake2bVector256.IsSupported)
		{
			Blake2bVector256.Compress(ref _state[0], _source, 128, 0);
		}
	}
}
