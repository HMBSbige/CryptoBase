using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Hashes.Sha256;
using CryptoBase.Hashes.Sha384;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kdf;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Tls12PrfBenchmark
{
	private const string Label = "key expansion";

	// 32 bytes is a single block, 48 bytes is a master secret, and 128 and 256 bytes cover key blocks.
	[Params(32, 48, 128, 256)]
	public int OutputLength { get; set; }

	private byte[] _secret = [];
	private byte[] _seed = [];
	private byte[] _output = [];
	private TlsSecret _bouncyCastleSecret = null!;

	[GlobalSetup]
	public void Setup()
	{
		_secret = RandomNumberGenerator.GetBytes(48);
		_seed = RandomNumberGenerator.GetBytes(64);
		_output = new byte[OutputLength];
		_bouncyCastleSecret = new BcTlsCrypto().CreateSecret(_secret);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-256")]
	public void BouncyCastleSha256()
	{
		_bouncyCastleSecret.DeriveUsingPrf(PrfAlgorithm.tls_prf_sha256, Label, _seed, OutputLength).ExtractTo(_output);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256")]
	public void CryptoBaseSha256()
	{
		Tls12Prf.DeriveKey<Sha256HashAlgorithm>(_secret, "key expansion"u8, _seed, _output);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256")]
	public void GenericSha256()
	{
		Tls12Prf<HmacAlgorithm<Sha256HashAlgorithm>>.DeriveKey(_secret, "key expansion"u8, _seed, _output);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-256")]
	public void PlatformSha256()
	{
		Tls12Prf<PlatformHmacSha256>.DeriveKey(_secret, "key expansion"u8, _seed, _output);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("SHA-384")]
	public void BouncyCastleSha384()
	{
		_bouncyCastleSecret.DeriveUsingPrf(PrfAlgorithm.tls_prf_sha384, Label, _seed, OutputLength).ExtractTo(_output);
	}

	[Benchmark]
	[BenchmarkCategory("SHA-384")]
	public void CryptoBaseSha384()
	{
		Tls12Prf.DeriveKey<Sha384HashAlgorithm>(_secret, "key expansion"u8, _seed, _output);
	}
}
