using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests;
using System;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA256Benchmark
{
	[Params(32, 114514)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = Utils.RandBytes(ByteLength).ToArray();
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha256Length];
		using var sha256 = DigestUtils.Create(DigestType.Sha256);
		sha256.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha256Length];
		using var sha256 = new BcSHA256Digest();
		sha256.UpdateFinal(_randombytes.Span, hash);
	}
}
