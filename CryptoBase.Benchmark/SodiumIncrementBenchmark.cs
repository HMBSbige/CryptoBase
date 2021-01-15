using BenchmarkDotNet.Attributes;
using System;
using System.Linq;

namespace CryptoBase.Benchmark
{
	[MemoryDiagnoser]
	public class SodiumIncrementBenchmark
	{
		private byte[] _randombytes = Array.Empty<byte>();

		[Params(1, 100, 10000, 1000000)]
		public int Max { get; set; }

		[GlobalSetup]
		public void Setup()
		{
			_randombytes = Utils.RandBytes(4).ToArray();
		}

		[Benchmark(Baseline = true)]
		public void Increment()
		{
			var a = _randombytes.ToArray();
			for (var i = 0; i < Max; ++i)
			{
				a.Increment();
			}
		}

		[Benchmark]
		public void Increment_Int()
		{
			var a = _randombytes.ToArray();
			for (var i = 0; i < Max; ++i)
			{
				a.Increment_Int();
			}
		}
	}
}
