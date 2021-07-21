using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class CBCBenchmark
	{
		[Params(10000)]
		public int Max { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey16 = null!;
		private byte[] _randomIv16 = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(16).ToArray();
			_randomKey16 = Utils.RandBytes(16).ToArray();
			_randomIv16 = new byte[16];
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

		[Benchmark(Baseline = true)]
		public void AESEncrypt()
		{
			TestEncrypt(AESUtils.CreateECB(_randomKey16), _randombytes.Span);
		}

		[Benchmark]
		public void AESCBCEncrypt()
		{
			TestEncrypt(AESUtils.CreateCBC(_randomKey16, _randomIv16), _randombytes.Span);
		}
	}
}
