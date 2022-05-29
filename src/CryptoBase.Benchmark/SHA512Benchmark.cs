using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SHA512;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA512Benchmark
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
	public void BCrypt()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha512Length];
		using DefaultSHA512Digest sha512 = new();
		sha512.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha512Length];
		using BcSHA512Digest sha512 = new();
		sha512.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark(Baseline = true)]
	public void Native()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha512Length];
		using NativeSHA512Digest sha512 = new();
		sha512.UpdateFinal(_randombytes.Span, hash);
	}
}
