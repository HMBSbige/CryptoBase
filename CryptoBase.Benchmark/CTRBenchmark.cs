using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class CTRBenchmark
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
			Test(new ChaCha20OriginalCryptoX86(_randomKey16, _randomIv8), _randombytes.Span);
		}

		[Benchmark]
		public void AESCTR()
		{
			Test(AESUtils.CreateCTR(_randomKey16, _randomIv16), _randombytes.Span);
		}

		[Benchmark]
		public void SM4CTR()
		{
			Test(new CTRStreamMode(new SM4Crypto(_randomKey16), _randomIv16), _randombytes.Span);
		}
	}
}
