using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SHA384Benchmark
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
		Span<byte> hash = stackalloc byte[HashConstants.Sha384Length];
		using var sha384 = DigestUtils.Create(DigestType.Sha384);
		sha384.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Sha384Length];
		using var sha384 = new BcSHA384Digest();
		sha384.UpdateFinal(_randombytes.Span, hash);
	}
}
