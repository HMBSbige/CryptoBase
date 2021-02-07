using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class AESBenchmark
	{
		[Params(16, 24, 32)]
		public int KeyLength { get; set; }

		[Params(10000)]
		public int Max { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(16).ToArray();
			_randomKey = Utils.RandBytes(KeyLength).ToArray();
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
			TestEncrypt(new BcAESCrypto(true, _randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void SlowEncrypt()
		{
			TestEncrypt(new SlowAESCrypto(_randomKey), _randombytes.Span);
		}

		[Benchmark(Baseline = true)]
		public void FastEncrypt()
		{
			TestEncrypt(AESUtils.CreateECB(_randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void NormalEncrypt()
		{
			TestEncrypt(new AESECBCrypto(_randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void BouncyCastleDecrypt()
		{
			TestDecrypt(new BcAESCrypto(false, _randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void SlowDecrypt()
		{
			TestDecrypt(new SlowAESCrypto(_randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void FastDecrypt()
		{
			TestDecrypt(AESUtils.CreateECB(_randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void NormalDecrypt()
		{
			TestDecrypt(new AESECBCrypto(_randomKey), _randombytes.Span);
		}
	}
}
