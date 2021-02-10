using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class GCMBenchmark
	{
		[Params(1000000)]
		public int Length { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey = null!;
		private Memory<byte> _randomIv = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(Length).ToArray();
			_randomKey = Utils.RandBytes(16).ToArray();
			_randomIv = Utils.RandBytes(12).ToArray();
		}

		private void TestEncrypt(IAEADCrypto crypto)
		{
			Span<byte> o = stackalloc byte[Length];
			Span<byte> tag = stackalloc byte[16];

			crypto.Encrypt(_randomIv.Span, _randombytes.Span, o, tag);

			crypto.Dispose();
		}

		[Benchmark(Baseline = true)]
		public void NormalEncrypt()
		{
			TestEncrypt(new NormalAesGcmCrypto(_randomKey));
		}

		[Benchmark]
		public void BouncyCastleEncrypt()
		{
			TestEncrypt(new BcAesGcmCrypto(_randomKey));
		}

		[Benchmark]
		public void SlowEncrypt()
		{
			TestEncrypt(new GcmCryptoMode(AESUtils.CreateECB(_randomKey)));
		}
	}
}
