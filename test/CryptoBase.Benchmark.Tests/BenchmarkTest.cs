namespace CryptoBase.Benchmark.Tests;

public class BenchmarkTest
{
	[Fact]
	public void MD5Benchmark()
	{
		BenchmarkRunner.Run<MD5Benchmark>();
	}

	[Fact]
	public void SHA1Benchmark()
	{
		BenchmarkRunner.Run<SHA1Benchmark>();
	}

	[Fact]
	public void SM3Benchmark()
	{
		BenchmarkRunner.Run<SM3Benchmark>();
	}

	[Fact]
	public void RC4Benchmark()
	{
		BenchmarkRunner.Run<RC4Benchmark>();
	}

	[Fact]
	public void Salsa20Benchmark()
	{
		BenchmarkRunner.Run<Salsa20Benchmark>();
	}

	[Fact]
	public void XSalsa20Benchmark()
	{
		BenchmarkRunner.Run<XSalsa20Benchmark>();
	}

	[Fact]
	public void ChaCha20OriginalBenchmark()
	{
		BenchmarkRunner.Run<ChaCha20OriginalBenchmark>();
	}

	[Fact]
	public void ChaCha20Benchmark()
	{
		BenchmarkRunner.Run<ChaCha20Benchmark>();
	}

	[Fact]
	public void XChaCha20Benchmark()
	{
		BenchmarkRunner.Run<XChaCha20Benchmark>();
	}

	[Fact]
	public void AESBenchmark()
	{
		BenchmarkRunner.Run<AESBenchmark>();
	}

	[Fact]
	public void SM4Benchmark()
	{
		BenchmarkRunner.Run<SM4Benchmark>();
	}

	[Fact]
	public void SM4CTRBenchmark()
	{
		BenchmarkRunner.Run<SM4CTRBenchmark>();
	}

	[Fact]
	public void CTRBenchmark()
	{
		BenchmarkRunner.Run<CTRBenchmark>();
	}

	[Fact]
	public void CBCBenchmark()
	{
		BenchmarkRunner.Run<CBCBenchmark>();
	}

	[Fact]
	public void CFBBenchmark()
	{
		BenchmarkRunner.Run<CFBBenchmark>();
	}

	[Fact]
	public void GCMBenchmark()
	{
		BenchmarkRunner.Run<GCMBenchmark>();
	}

	[Fact]
	public void GHashBenchmark()
	{
		BenchmarkRunner.Run<GHashBenchmark>();
	}

	[Fact]
	public void ChaCha20Poly1305Benchmark()
	{
		BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
	}

	[Fact]
	public void XChaCha20Poly1305Benchmark()
	{
		BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();
	}

	[Fact]
	public void Poly1305Benchmark()
	{
		BenchmarkRunner.Run<Poly1305Benchmark>();
	}

	[Fact]
	public void Base32Benchmark()
	{
		BenchmarkRunner.Run<Base32Benchmark>();
	}

	[Fact]
	public void SHA224Benchmark()
	{
		BenchmarkRunner.Run<SHA224Benchmark>();
	}

	[Fact]
	public void SHA256Benchmark()
	{
		BenchmarkRunner.Run<SHA256Benchmark>();
	}

	[Fact]
	public void SHA384Benchmark()
	{
		BenchmarkRunner.Run<SHA384Benchmark>();
	}

	[Fact]
	public void SHA512Benchmark()
	{
		BenchmarkRunner.Run<SHA512Benchmark>();
	}

	[Fact]
	public void HMACBenchmark()
	{
		BenchmarkRunner.Run<HMACBenchmark>();
	}

	[Fact]
	public void HKDFBenchmark()
	{
		BenchmarkRunner.Run<HKDFBenchmark>();
	}

	[Fact]
	public void CRC32Benchmark()
	{
		BenchmarkRunner.Run<CRC32Benchmark>();
	}

	[Fact]
	public void Xor16Benchmark()
	{
		BenchmarkRunner.Run<Xor16Benchmark>();
	}

	[Fact]
	public void Xor64Benchmark()
	{
		BenchmarkRunner.Run<Xor64Benchmark>();
	}

	[Fact]
	public void XorBenchmark()
	{
		BenchmarkRunner.Run<XorBenchmark>();
	}
}
