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
		public void SHA1Benchmark()
		{
			var _ = BenchmarkRunner.Run<SHA1Benchmark>();
		}

		[TestMethod]
		public void SM3Benchmark()
		{
			var _ = BenchmarkRunner.Run<SM3Benchmark>();
		}

		[TestMethod]
		public void RC4Benchmark()
		{
			var _ = BenchmarkRunner.Run<RC4Benchmark>();
		}

		[TestMethod]
		public void Salsa20Benchmark()
		{
			var _ = BenchmarkRunner.Run<Salsa20Benchmark>();
		}

		[TestMethod]
		public void XSalsa20Benchmark()
		{
			var _ = BenchmarkRunner.Run<XSalsa20Benchmark>();
		}

		[TestMethod]
		public void ChaCha20OriginalBenchmark()
		{
			var _ = BenchmarkRunner.Run<ChaCha20OriginalBenchmark>();
		}
	}
}
