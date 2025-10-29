using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class AesBenchmark
{
	[Params(16, 24, 32)]
	public int KeyLength { get; set; }

	[Params(1000)]
	public int Max { get; set; }

	private Memory<byte> _randombytes;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes = RandomNumberGenerator.GetBytes(16);
		_randomKey = RandomNumberGenerator.GetBytes(KeyLength);
	}

	private void TestEncrypt(IBlockCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (int i = 0; i < Max; ++i)
		{
			crypto.Encrypt(origin, o);
		}

		crypto.Dispose();
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		TestEncrypt(new BcAesCrypto(_randomKey), _randombytes.Span);
	}

	[Benchmark(Baseline = true)]
	public void X86Encrypt()
	{
		TestEncrypt(AesCrypto.CreateCore(_randomKey), _randombytes.Span);
	}

	[Benchmark]
	public void DefaultEncrypt()
	{
		TestEncrypt(new DefaultAesCrypto(_randomKey), _randombytes.Span);
	}
}
