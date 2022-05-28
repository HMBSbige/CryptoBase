using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SHA1;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA1Benchmark
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
	public void Bcrypt()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha1Length];
		using DefaultSHA1Digest sha1 = new();
		sha1.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha1Length];
		using BcSHA1Digest sha1 = new();
		sha1.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark(Baseline = true)]
	public void Native()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha1Length];
		using NativeSHA1Digest sha1 = new();
		sha1.UpdateFinal(_randombytes.Span, hash);
	}
}
