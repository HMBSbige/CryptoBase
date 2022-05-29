using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SM3;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SM3Benchmark
{
	[Params(32, 1024, 1024 * 1024)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.SM3Length];
		using BcSM3Digest sm3 = new();
		sm3.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void Manage()
	{
		Span<byte> hash = stackalloc byte[HashConstants.SM3Length];
		using SM3Digest sm3 = new();
		sm3.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark(Baseline = true)]
	public void Native()
	{
		Span<byte> hash = stackalloc byte[HashConstants.SM3Length];
		using NativeSM3Digest sm3 = new();
		sm3.UpdateFinal(_randombytes.Span, hash);
	}
}
