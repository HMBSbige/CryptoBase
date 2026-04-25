using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
using CryptoBase.Macs.Poly1305;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class Poly1305Benchmark
{
	[Params(16, 1024, 8192)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(32);
	}

	private void Test<T>(T mac) where T : IMac, allows ref struct
	{
		Span<byte> o = stackalloc byte[16];

		mac.Update(_randombytes.Span);
		mac.GetMac(o);

		mac.Dispose();
	}

	[Benchmark]
	public void SoftwareFallback()
	{
		Test(new Poly1305SF(_randomKey));
	}

	[Benchmark(Baseline = true)]
	public void X86()
	{
		Test(new Poly1305X86(_randomKey));
	}
}
