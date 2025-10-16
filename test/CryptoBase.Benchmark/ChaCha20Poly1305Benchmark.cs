using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class ChaCha20Poly1305Benchmark
{
	[Params(1024, 8192, 1000000)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private Memory<byte> _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(32);
		_randomIv = RandomNumberGenerator.GetBytes(12);
	}

	private void TestEncrypt(IAEADCrypto crypto)
	{
		Span<byte> o = stackalloc byte[Length];
		Span<byte> tag = stackalloc byte[16];

		for (int i = 0; i < 1000; i++)
		{
			crypto.Encrypt(_randomIv.Span, _randombytes.Span, o, tag);
		}

		crypto.Dispose();
	}

	[Benchmark(Baseline = true)]
	public void DefaultEncrypt()
	{
		TestEncrypt(new DefaultChaCha20Poly1305Crypto(_randomKey));
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		TestEncrypt(new BcChaCha20Poly1305Crypto(_randomKey));
	}

	[Benchmark]
	public void Encrypt()
	{
		TestEncrypt(new ChaCha20Poly1305Crypto(_randomKey));
	}
}
