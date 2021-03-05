using BenchmarkDotNet.Attributes;
using CryptoBase.Abstractions;
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
		public void SoftwareFallback()
		{
			Test(new GHashSF(_randomKey));
		}

		[Benchmark(Baseline = true)]
		public void X86()
		{
			Test(new GHashX86(_randomKey));
		}
	}
}
