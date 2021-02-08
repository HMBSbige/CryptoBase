using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class CFBBenchmark
	{
		[Params(1000000)]
		public int ByteLength { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey16 = null!;
		private byte[] _randomIv8 = null!;
		private byte[] _randomIv16 = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(ByteLength).ToArray();
			_randomKey16 = Utils.RandBytes(16).ToArray();
			_randomIv8 = Utils.RandBytes(8).ToArray();
			_randomIv16 = Utils.RandBytes(16).ToArray();
		}

		private static void Test(IStreamCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];
			crypto.Update(origin, o);

			crypto.Dispose();
		}

		[Benchmark(Baseline = true)]
		public void ChaCha20()
		{
			Test(new FastChaCha20OriginalCrypto(_randomKey16, _randomIv8), _randombytes.Span);
		}

		[Benchmark]
		public void AESCFB()
		{
			Test(AESUtils.CreateCFB(true, _randomKey16, _randomIv16), _randombytes.Span);
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Test(new BcAESCFBStreamCrypto(true, _randomKey16, _randomIv16), _randombytes.Span);
		}
	}
}
