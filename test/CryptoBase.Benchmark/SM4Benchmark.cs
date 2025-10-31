using BenchmarkDotNet.Attributes;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class SM4Benchmark
{
	[Params(1024, 8192)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(16);
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		using BcSm4Crypto crypto = new(_randomKey);

		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[1 * 16];

		int count = origin.Length / (1 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt(origin.Slice(i * 16), o);
		}
	}

	[Benchmark]
	public void Encrypt()
	{
		using SM4Crypto crypto = new(_randomKey);

		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[1 * 16];

		int count = origin.Length / (1 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt(origin.Slice(i * 1 * 16), o);
		}
	}

	[Benchmark]
	public void Encrypt4()
	{
		using SM4Crypto crypto = new(_randomKey);

		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[4 * 16];

		int count = origin.Length / (4 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt4(origin.Slice(i * 4 * 16), o);
		}
	}

	[Benchmark]
	public void Encrypt8()
	{
		using SM4Crypto crypto = new(_randomKey);

		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[8 * 16];

		int count = origin.Length / (8 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt8(origin.Slice(i * 8 * 16), o);
		}
	}

	[Benchmark(Baseline = true)]
	public void Encrypt16()
	{
		using SM4Crypto crypto = new(_randomKey);

		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[16 * 16];

		int count = origin.Length / (16 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt16(origin.Slice(i * 16 * 16), o);
		}
	}
}
