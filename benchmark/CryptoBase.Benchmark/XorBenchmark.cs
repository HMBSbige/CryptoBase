using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XorBenchmark
{
	[Params(16, 64, 1024, 8191, 8192)]
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

	[Benchmark]
	public void Normal()
	{
		ReadOnlySpan<byte> a = _a;
		ReadOnlySpan<byte> b = _b;
		Span<byte> destination = _destination;

		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = (byte)(a[i] ^ b[i]);
		}
	}

	[Benchmark(Baseline = true)]
	public void FastUtilsXor()
	{
		FastUtils.Xor(_a, _b, _destination, ByteLength);
	}
}
