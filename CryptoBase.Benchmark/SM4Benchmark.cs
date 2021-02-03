using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.BlockCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class SM4Benchmark
	{
		[Params(1, 10000)]
		public int Max { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(16).ToArray();
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

		private void TestDecrypt(IBlockCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];

			for (var i = 0; i < Max; ++i)
			{
				crypto.Decrypt(origin, o);
			}

			crypto.Dispose();
		}

		[Benchmark(Baseline = true)]
		public void BouncyCastleEncrypt()
		{
			TestEncrypt(new BcSM4Crypto(true, _randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void SlowEncrypt()
		{
			TestEncrypt(new SlowSM4Crypto(_randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void BouncyCastleDecrypt()
		{
			TestDecrypt(new BcSM4Crypto(false, _randomKey), _randombytes.Span);
		}

		[Benchmark]
		public void SlowDecrypt()
		{
			TestDecrypt(new SlowSM4Crypto(_randomKey), _randombytes.Span);
		}
	}
}
