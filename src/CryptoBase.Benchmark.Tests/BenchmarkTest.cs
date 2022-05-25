namespace CryptoBase.Benchmark.Tests;

[TestClass]
public class BenchmarkTest
{
	[TestMethod]
	public void SodiumIncrementBenchmark()
	{
		BenchmarkRunner.Run<SodiumIncrementBenchmark>();
	}

	[TestMethod]
	public void MD5Benchmark()
	{
		BenchmarkRunner.Run<MD5Benchmark>();
	}

	[TestMethod]
	public void SHA1Benchmark()
	{
		BenchmarkRunner.Run<SHA1Benchmark>();
	}

	[TestMethod]
	public void SM3Benchmark()
	{
		BenchmarkRunner.Run<SM3Benchmark>();
	}

	[TestMethod]
	public void RC4Benchmark()
	{
		BenchmarkRunner.Run<RC4Benchmark>();
	}

	[TestMethod]
	public void Salsa20Benchmark()
	{
		BenchmarkRunner.Run<Salsa20Benchmark>();
	}

	[TestMethod]
	public void XSalsa20Benchmark()
	{
		BenchmarkRunner.Run<XSalsa20Benchmark>();
	}

	[TestMethod]
	public void ChaCha20OriginalBenchmark()
	{
		BenchmarkRunner.Run<ChaCha20OriginalBenchmark>();
	}

	[TestMethod]
	public void ChaCha20Benchmark()
	{
		BenchmarkRunner.Run<ChaCha20Benchmark>();
	}

	[TestMethod]
	public void XChaCha20Benchmark()
	{
		BenchmarkRunner.Run<XChaCha20Benchmark>();
	}

	[TestMethod]
	public void AESBenchmark()
	{
		BenchmarkRunner.Run<AESBenchmark>();
	}

	[TestMethod]
	public void SM4Benchmark()
	{
		BenchmarkRunner.Run<SM4Benchmark>();
	}

	[TestMethod]
	public void CTRBenchmark()
	{
		BenchmarkRunner.Run<CTRBenchmark>();
	}

	[TestMethod]
	public void CBCBenchmark()
	{
		BenchmarkRunner.Run<CBCBenchmark>();
	}

	[TestMethod]
	public void CFBBenchmark()
	{
		BenchmarkRunner.Run<CFBBenchmark>();
	}

	[TestMethod]
	public void GCMBenchmark()
	{
		BenchmarkRunner.Run<GCMBenchmark>();
	}

	[TestMethod]
	public void GHashBenchmark()
	{
		BenchmarkRunner.Run<GHashBenchmark>();
	}

	[TestMethod]
	public void ChaCha20Poly1305Benchmark()
	{
		BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
	}

	[TestMethod]
	public void XChaCha20Poly1305Benchmark()
	{
		BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();
	}

	[TestMethod]
	public void Poly1305Benchmark()
	{
		BenchmarkRunner.Run<Poly1305Benchmark>();
	}

	[TestMethod]
	public void HexExtensionsBenchmark()
	{
		BenchmarkRunner.Run<HexExtensionsBenchmark>();
	}

	[TestMethod]
	public void Base32Benchmark()
	{
		BenchmarkRunner.Run<Base32Benchmark>();
	}

	[TestMethod]
	public void SHA256Benchmark()
	{
		BenchmarkRunner.Run<SHA256Benchmark>();
	}

	[TestMethod]
	public void SHA384Benchmark()
	{
		BenchmarkRunner.Run<SHA384Benchmark>();
	}

	[TestMethod]
	public void SHA512Benchmark()
	{
		BenchmarkRunner.Run<SHA512Benchmark>();
	}

	[TestMethod]
	public void HMACBenchmark()
	{
		BenchmarkRunner.Run<HMACBenchmark>();
	}

	[TestMethod]
	public void HKDFBenchmark()
	{
		BenchmarkRunner.Run<HKDFBenchmark>();
	}

	[TestMethod]
	public void CRC32Benchmark()
	{
		BenchmarkRunner.Run<CRC32Benchmark>();
	}
}
