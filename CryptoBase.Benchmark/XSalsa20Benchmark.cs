using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.BouncyCastle.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class XSalsa20Benchmark
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

		private static void Test(IStreamCrypto crypto, Span<byte> origin)
		{
			Span<byte> o = stackalloc byte[origin.Length];
			crypto.Update(origin, o);

			crypto.Dispose();
		}

		[Benchmark]
		public void BouncyCastle()
		{
			Test(new BcXSalsa20Crypto(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark]
		public void SoftwareFallback()
		{
			Test(new XSalsa20CryptoSF(_randomKey, _randomIv), _randombytes.Span);
		}

		[Benchmark(Baseline = true)]
		public void X86()
		{
			Test(new XSalsa20CryptoX86(_randomKey, _randomIv), _randombytes.Span);
		}
	}
}
