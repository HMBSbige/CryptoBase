using BenchmarkDotNet.Running;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using UnitTest.Benchmarks;

namespace UnitTest
{
	[TestClass]
	public class BenchmarkTest
	{
		[TestMethod]
		public void MD5Test()
		{
			var _ = BenchmarkRunner.Run<MD5Benchmark>();
		}
	}
}
