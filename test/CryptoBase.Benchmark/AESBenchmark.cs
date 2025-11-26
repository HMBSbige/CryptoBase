using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
[RankColumn]
public class AesBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(1024, 8192)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(KeyLength);
	}

	private void Encrypt(IBlockCrypto crypto)
	{
		ReadOnlySpan<byte> origin = _randombytes.Span;
		Span<byte> o = stackalloc byte[16 * 16];

		int count = origin.Length / (16 * 16);

		for (int i = 0; i < count; ++i)
		{
			crypto.Encrypt16(origin.Slice(i * 16 * 16), o);
		}
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		using BcAesCrypto crypto = new(_randomKey);
		Encrypt(crypto);
	}

	[Benchmark]
	public void DefaultEncrypt()
	{
		using DefaultAesCrypto crypto = new(_randomKey);
		Encrypt(crypto);
	}

	[Benchmark(Baseline = true)]
	public void Encrypt()
	{
		using AesCrypto crypto = AesCrypto.CreateCore(_randomKey);
		Encrypt(crypto);
	}
}
