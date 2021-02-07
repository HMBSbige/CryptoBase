using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class CBCBenchmark
	{
		[Params(10000)]
		public int Max { get; set; }

		private Memory<byte> _randombytes;
		private Memory<byte> _randombytesChaCha20;
		private byte[] _randomKey16 = null!;
		private byte[] _randomIv8 = null!;
		private byte[] _randomIv16 = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = new byte[16];
			_randombytesChaCha20 = new byte[16 * Max];
			_randomKey16 = Utils.RandBytes(16).ToArray();
			_randomIv8 = new byte[8];
			_randomIv16 = new byte[16];
		}

		private static void Test(IStreamCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];
			crypto.Update(origin, o);

			crypto.Dispose();
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
		public void ChaCha20()
		{
			Test(new FastChaCha20OriginalCrypto(_randomKey16, _randomIv8), _randombytesChaCha20.Span);
		}

		[Benchmark]
		public void FastAESCBCEncrypt()
		{
			TestEncrypt(new CBCBlockMode(AESUtils.CreateECB(_randomKey16), _randomIv16), _randombytes.Span);
		}
	}
}
