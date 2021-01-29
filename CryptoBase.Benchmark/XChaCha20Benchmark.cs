using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class XChaCha20Benchmark
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
			_randomIv = Utils.RandBytes(24).ToArray();
		}

		private static void Test(ISymmetricCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];
			crypto.Encrypt(origin, o);

			crypto.Dispose();
		}

		[Benchmark(Baseline = true)]
		public void BouncyCastle()
		{
			Test(new BcXChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark]
		public void Slow()
		{
			Test(new SlowXChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark]
		public void Fast()
		{
			Test(new FastXChaCha20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}
	}
}
