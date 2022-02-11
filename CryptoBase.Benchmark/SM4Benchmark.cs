using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SM4Benchmark
{
	[Params(1000000)]
	public int Max { get; set; }

	private Memory<byte> _randombytes16;
	private Memory<byte> _randombytes64;
	private Memory<byte> _randombytes128;
	private Memory<byte> _randombytes256;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes16 = RandomNumberGenerator.GetBytes(16);
		_randombytes64 = RandomNumberGenerator.GetBytes(64);
		_randombytes128 = RandomNumberGenerator.GetBytes(128);
		_randombytes256 = RandomNumberGenerator.GetBytes(256);
		_randomKey = RandomNumberGenerator.GetBytes(16);
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

	private void TestDecrypt(IBlockCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (int i = 0; i < Max; ++i)
		{
			crypto.Decrypt(origin, o);
		}

		crypto.Dispose();
	}

	[Benchmark]
	public void BouncyCastleEncrypt()
	{
		TestEncrypt(new BcSM4Crypto(true, _randomKey), _randombytes16.Span);
	}

	[Benchmark(Baseline = true)]
	public void Encrypt()
	{
		TestEncrypt(new SM4Crypto(_randomKey), _randombytes16.Span);
	}

	[Benchmark]
	public void BouncyCastleDecrypt()
	{
		TestDecrypt(new BcSM4Crypto(false, _randomKey), _randombytes16.Span);
	}

	[Benchmark]
	public void Decrypt()
	{
		TestDecrypt(new SM4Crypto(_randomKey), _randombytes16.Span);
	}

	[Benchmark]
	public void Encrypt4()
	{
		TestEncrypt(new SM4CryptoX86(_randomKey), _randombytes64.Span);
	}

	[Benchmark]
	public void Encrypt8()
	{
		TestEncrypt(new SM4CryptoBlock8X86(_randomKey), _randombytes128.Span);
	}

	[Benchmark]
	public void Encrypt16()
	{
		TestEncrypt(new SM4CryptoBlock16X86(_randomKey), _randombytes256.Span);
	}
}
