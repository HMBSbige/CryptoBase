using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.Digests;
using CryptoBase.BouncyCastle.Digests;
using CryptoBase.Digests.MD5;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class MD5Benchmark
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
		Span<byte> buffer = stackalloc byte[HashConstants.Md5Length];
		using DefaultMD5Digest md5 = new();
		md5.UpdateFinal(_randombytes.Span, buffer);
	}

	[Benchmark]
	public void BouncyCastle()
	{
		Span<byte> buffer = stackalloc byte[HashConstants.Md5Length];
		using BcMD5Digest md5 = new();
		md5.UpdateFinal(_randombytes.Span, buffer);
	}

	[Benchmark]
	public void Manage()
	{
		Span<byte> buffer = stackalloc byte[HashConstants.Md5Length];
		using MD5Digest md5 = new();
		md5.UpdateFinal(_randombytes.Span, buffer);
	}

	[Benchmark(Baseline = true)]
	public void Rust()
	{
		Span<byte> buffer = stackalloc byte[HashConstants.Md5Length];
		using NativeMD5Digest md5 = new();
		md5.UpdateFinal(_randombytes.Span, buffer);
	}
}
