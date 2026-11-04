using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.KeyAgreements.Xdh;
using Org.BouncyCastle.Security;
using BouncyCastleX448 = Org.BouncyCastle.Math.EC.Rfc7748.X448;

namespace CryptoBase.Benchmark.KeyAgreements;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class X448Benchmark
{
	private readonly byte[] _privateKey = new byte[X448.PrivateKeyLength];
	private readonly byte[] _scratchPrivateKey = new byte[X448.PrivateKeyLength];
	private readonly byte[] _publicKey = new byte[X448.PublicKeyLength];
	private readonly byte[] _peerPublicKey = new byte[X448.PublicKeyLength];
	private readonly byte[] _sharedSecret = new byte[X448.SharedSecretLength];
	private readonly SecureRandom _random = new();
	private X448 _cryptoBase = null!;

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = X448.GenerateKey();
		_cryptoBase.ExportPrivateKey(_privateKey);

		using (X448 peer = X448.GenerateKey())
		{
			peer.ExportPublicKey(_peerPublicKey);
		}

		BouncyCastleX448.Precompute();
		byte[] expectedPublicKey = new byte[X448.PublicKeyLength];
		_cryptoBase.ExportPublicKey(expectedPublicKey);
		BouncyCastleDerivePublicKey();

		if (!_publicKey.AsSpan().SequenceEqual(expectedPublicKey))
		{
			throw new InvalidOperationException("Benchmark implementations derived different public keys.");
		}

		if (!CryptoBaseDeriveSharedSecret())
		{
			throw new InvalidOperationException("The peer public key was rejected.");
		}

		byte[] expected = _sharedSecret.AsSpan().ToArray();

		if (!BouncyCastleDeriveSharedSecret() || !_sharedSecret.AsSpan().SequenceEqual(expected))
		{
			throw new InvalidOperationException("Benchmark implementations derived different shared secrets.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseGenerateKey()
	{
		using X448 key = X448.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BouncyCastleGenerateKey()
	{
		BouncyCastleX448.GeneratePrivateKey(_random, _scratchPrivateKey);
		BouncyCastleX448.GeneratePublicKey(_scratchPrivateKey, _publicKey);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPrivateKey")]
	public void CryptoBaseDerivePublicKey()
	{
		using X448 key = X448.ImportPrivateKey(_privateKey);
	}

	[Benchmark]
	[BenchmarkCategory("ImportPrivateKey")]
	public void BouncyCastleDerivePublicKey()
	{
		BouncyCastleX448.GeneratePublicKey(_privateKey, _publicKey);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("DeriveSharedSecret")]
	public bool CryptoBaseDeriveSharedSecret()
	{
		return _cryptoBase.TryDeriveSharedSecret(_peerPublicKey, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveSharedSecret")]
	public bool BouncyCastleDeriveSharedSecret()
	{
		return BouncyCastleX448.CalculateAgreement(_privateKey, _peerPublicKey, _sharedSecret);
	}
}
