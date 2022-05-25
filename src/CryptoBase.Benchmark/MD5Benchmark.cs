using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.MD5;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class MD5Benchmark
{
	[Params(16 + 6, 16 + 16, 114514)]
	public int ByteLength { get; set; }

	private Memory<byte> _randombytes;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(ByteLength);
	}

	[Benchmark]
	public void Default()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
		using var md5 = new DefaultMD5Digest();
		md5.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
		using var md5 = new BcMD5Digest();
		md5.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark]
	public void MayFast()
	{
		Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
		using var md5 = new MD5Digest();
		md5.UpdateFinal(_randombytes.Span, hash);
	}

	[Benchmark(Baseline = true)]
	public void Fast440()
	{
		if (_randombytes.Length > 55)
		{
			return;
		}
		Span<byte> hash = stackalloc byte[HashConstants.Md5Length];
		using var md5 = new Fast440MD5Digest();
		md5.UpdateFinal(_randombytes.Span, hash);
	}
}
