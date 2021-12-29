using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System;

namespace CryptoBase.Benchmark;

[MemoryDiagnoser]
public class SM4Benchmark
{
	[Params(1000000)]
	public int Max { get; set; }

	private Memory<byte> _randombytes16;
	private Memory<byte> _randombytes64;
	private byte[] _randomKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_randombytes16 = Utils.RandBytes(16).ToArray();
		_randombytes64 = Utils.RandBytes(64).ToArray();
		_randomKey = Utils.RandBytes(16).ToArray();
	}

	private void TestEncrypt(IBlockCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (var i = 0; i < Max; ++i)
		{
			crypto.Encrypt(origin, o);
		}

		crypto.Dispose();
	}

	private void TestEncrypt4(IBlockCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (var i = 0; i < Max; ++i)
		{
			crypto.Encrypt4(origin, o);
		}

		crypto.Dispose();
	}

	private void TestDecrypt(IBlockCrypto crypto, Span<byte> origin)
	{
		Span<byte> o = stackalloc byte[origin.Length];

		for (var i = 0; i < Max; ++i)
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
	public void BouncyCastleEncrypt4()
	{
		TestEncrypt4(new BcSM4Crypto(true, _randomKey), _randombytes64.Span);
	}

	[Benchmark]
	public void Encrypt4()
	{
		TestEncrypt4(new SM4Crypto(_randomKey), _randombytes64.Span);
	}
}
