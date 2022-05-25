using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class XChaCha20Poly1305Benchmark
{
	[Params(1000000)]
	public int Length { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;
	private Memory<byte> _randomIv = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(Length);
		_randomKey = RandomNumberGenerator.GetBytes(32);
		_randomIv = RandomNumberGenerator.GetBytes(24);
	}

	private void TestEncrypt(IAEADCrypto crypto)
	{
		Span<byte> o = stackalloc byte[Length];
		Span<byte> tag = stackalloc byte[16];

		crypto.Encrypt(_randomIv.Span, _randombytes.Span, o, tag);

		crypto.Dispose();
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		TestEncrypt(new BcXChaCha20Poly1305Crypto(_randomKey));
	}

	[Benchmark(Baseline = true)]
	public void Encrypt()
	{
		TestEncrypt(AEADCryptoCreate.XChaCha20Poly1305(_randomKey));
	}
}
