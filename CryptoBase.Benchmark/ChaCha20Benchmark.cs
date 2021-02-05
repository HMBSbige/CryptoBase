using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class ChaCha20Benchmark
	{
		[Params(32, 1000000)]
		public int ByteLength { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey = null!;
		private byte[] _randomIv = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(ByteLength).ToArray();
			_randomKey = Utils.RandBytes(32).ToArray();
			_randomIv = Utils.RandBytes(12).ToArray();
		}

		private static void Test(IStreamCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];
			crypto.Update(origin, o);

			crypto.Dispose();
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Test(new BcChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark]
		public void Slow()
		{
			Test(new SlowChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark(Baseline = true)]
		public void Fast()
		{
			Test(new FastChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}
	}
}
