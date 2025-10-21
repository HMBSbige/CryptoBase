using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[RankColumn]
public class XorBenchmark
{
	[Params(16, 64, 1024, 8192, 8191)]
	public int Length { get; set; }

	private Memory<byte> _a;
	private Memory<byte> _b;

	[GlobalSetup]
	public void Setup()
	{
		_a = RandomNumberGenerator.GetBytes(Length);
		_b = RandomNumberGenerator.GetBytes(Length);
	}

	[Benchmark(Description = @"Normal")]
	public void A()
	{
		Span<byte> dst = stackalloc byte[Length];
		ReadOnlySpan<byte> a = _a.Span;
		ReadOnlySpan<byte> b = _b.Span;

		for (int i = 0; i < Length; ++i)
		{
			dst[i] = (byte)(a[i] ^ b[i]);
		}
	}

	[Benchmark(Baseline = true, Description = @"FastUtils.Xor")]
	public void B()
	{
		Span<byte> dst = stackalloc byte[Length];
		Span<byte> a = _a.Span;
		Span<byte> b = _b.Span;

		FastUtils.Xor(a, b, dst, Length);
	}
}
