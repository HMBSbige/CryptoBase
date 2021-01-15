using BenchmarkDotNet.Running;
using CryptoBase.Benchmark;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest
{
	[TestClass]
	public class BenchmarkTest
	{
		[TestMethod]
		public void MD5Benchmark()
		{
			var _ = BenchmarkRunner.Run<MD5Benchmark>();
		}

		[TestMethod]
		public void SodiumIncrementBenchmark()
		{
			var _ = BenchmarkRunner.Run<SodiumIncrementBenchmark>();
		}
	}
}
