using BenchmarkDotNet.Running;
using CryptoBase.Benchmark;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest
{
	[TestClass]
	public class BenchmarkTest
	{
		[TestMethod]
		public void SodiumIncrementBenchmark()
		{
			var _ = BenchmarkRunner.Run<SodiumIncrementBenchmark>();
		}

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

		[TestMethod]
		public void ChaCha20Benchmark()
		{
			var _ = BenchmarkRunner.Run<ChaCha20Benchmark>();
		}

		[TestMethod]
		public void XChaCha20Benchmark()
		{
			var _ = BenchmarkRunner.Run<XChaCha20Benchmark>();
		}

		[TestMethod]
		public void AESBenchmark()
		{
			var _ = BenchmarkRunner.Run<AESBenchmark>();
		}

		[TestMethod]
		public void SM4Benchmark()
		{
			var _ = BenchmarkRunner.Run<SM4Benchmark>();
		}

		[TestMethod]
		public void CTRBenchmark()
		{
			var _ = BenchmarkRunner.Run<CTRBenchmark>();
		}

		[TestMethod]
		public void CBCBenchmark()
		{
			var _ = BenchmarkRunner.Run<CBCBenchmark>();
		}

		[TestMethod]
		public void CFBBenchmark()
		{
			var _ = BenchmarkRunner.Run<CFBBenchmark>();
		}

		[TestMethod]
		public void GCMBenchmark()
		{
			var _ = BenchmarkRunner.Run<GCMBenchmark>();
		}

		[TestMethod]
		public void GHashBenchmark()
		{
			var _ = BenchmarkRunner.Run<GHashBenchmark>();
		}

		[TestMethod]
		public void ChaCha20Poly1305Benchmark()
		{
			var _ = BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
		}

		[TestMethod]
		public void XChaCha20Poly1305Benchmark()
		{
			var _ = BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();
		}

		[TestMethod]
		public void Poly1305Benchmark()
		{
			var _ = BenchmarkRunner.Run<Poly1305Benchmark>();
		}

		[TestMethod]
		public void HexExtensionsBenchmark()
		{
			var _ = BenchmarkRunner.Run<HexExtensionsBenchmark>();
		}

		[TestMethod]
		public void Base32Benchmark()
		{
			var _ = BenchmarkRunner.Run<Base32Benchmark>();
		}

		[TestMethod]
		public void SHA256Benchmark()
		{
			var _ = BenchmarkRunner.Run<SHA256Benchmark>();
		}

		[TestMethod]
		public void SHA384Benchmark()
		{
			var _ = BenchmarkRunner.Run<SHA384Benchmark>();
		}

		[TestMethod]
		public void SHA512Benchmark()
		{
			var _ = BenchmarkRunner.Run<SHA512Benchmark>();
		}

		[TestMethod]
		public void HMACBenchmark()
		{
			var _ = BenchmarkRunner.Run<HMACBenchmark>();
		}
	}
}
