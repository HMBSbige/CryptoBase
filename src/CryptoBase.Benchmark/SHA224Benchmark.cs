using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.SHA224;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA224Benchmark
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
		Span<byte> hash = stackalloc byte[HashConstants.Sha224Length];
		using BcSHA224Digest sha224 = new();
		sha224.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark(Baseline = true)]
	public void Native()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha224Length];
		using NativeSHA224Digest sha224 = new();
		sha224.UpdateFinal(_randombytes.Span, hash);
	}
}
