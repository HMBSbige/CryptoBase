using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Macs.GHash;
using System;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class GHashBenchmark
	{
		[Params(32, 1000000)]
		public int Length { get; set; }

		private Memory<byte> _randombytes;
		private byte[] _randomKey = null!;

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(Length).ToArray();
			_randomKey = Utils.RandBytes(16).ToArray();
		}

		private void Test(IMac mac)
		{
			Span<byte> o = stackalloc byte[16];

			mac.Update(_randombytes.Span);
			mac.GetMac(o);

			mac.Dispose();
		}

		[Benchmark]
		public void Slow()
		{
			Test(new SlowGHash(_randomKey));
		}

		[Benchmark(Baseline = true)]
		public void Fast()
		{
			Test(new FastGHash(_randomKey));
		}
	}
}
