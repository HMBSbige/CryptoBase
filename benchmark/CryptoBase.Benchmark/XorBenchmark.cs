using BenchmarkDotNet.Attributes;
using System.Numerics.Tensors;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XorBenchmark
{
	[Params(16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 65536, 1048576)]
	public int ByteLength { get; set; }

	private byte[] _a = [];
	private byte[] _b = [];
	private byte[] _destination = [];

	[GlobalSetup]
	public void Setup()
	{
		_a = RandomNumberGenerator.GetBytes(ByteLength);
		_b = RandomNumberGenerator.GetBytes(ByteLength);
		_destination = new byte[ByteLength];
	}

	[Benchmark(Baseline = true)]
	public void CryptoBase()
	{
		FastUtils.Xor(_a, _b, _destination, ByteLength);
	}

	[Benchmark]
	public void DotNetTensorPrimitives()
	{
		TensorPrimitives.Xor(_a, _b, _destination);
	}
}
