using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests;
using System;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA1Benchmark
{
	[Params(32, 114514)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark(Baseline = true)]
	public void Default()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha1Length];
		using var sha1 = DigestUtils.Create(DigestType.Sha1);
		sha1.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha1Length];
		using var sha1 = new BcSHA1Digest();
		sha1.UpdateFinal(_randombytes.Span, hash);
	}
}
