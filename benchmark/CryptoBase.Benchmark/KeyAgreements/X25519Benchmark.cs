using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.KeyAgreements.Xdh;
using Org.BouncyCastle.Security;
using BouncyCastleX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace CryptoBase.Benchmark.KeyAgreements;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class X25519Benchmark
{
	private readonly byte[] _privateKey = new byte[X25519.PrivateKeyLength];
	private readonly byte[] _scratchPrivateKey = new byte[X25519.PrivateKeyLength];
	private readonly byte[] _publicKey = new byte[X25519.PublicKeyLength];
	private readonly byte[] _peerPublicKey = new byte[X25519.PublicKeyLength];
	private readonly byte[] _sharedSecret = new byte[X25519.SharedSecretLength];
	private readonly SecureRandom _random = new();
	private X25519 _cryptoBase = null!;

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = X25519.GenerateKey();
		_cryptoBase.ExportPrivateKey(_privateKey);

		using (X25519 peer = X25519.GenerateKey())
		{
			peer.ExportPublicKey(_peerPublicKey);
		}

		BouncyCastleX25519.Precompute();
		byte[] expectedPublicKey = new byte[X25519.PublicKeyLength];
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
		using X25519 key = X25519.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BouncyCastleGenerateKey()
	{
		BouncyCastleX25519.GeneratePrivateKey(_random, _scratchPrivateKey);
		BouncyCastleX25519.GeneratePublicKey(_scratchPrivateKey, _publicKey);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPrivateKey")]
	public void CryptoBaseDerivePublicKey()
	{
		using X25519 key = X25519.ImportPrivateKey(_privateKey);
	}

	[Benchmark]
	[BenchmarkCategory("ImportPrivateKey")]
	public void BouncyCastleDerivePublicKey()
	{
		BouncyCastleX25519.GeneratePublicKey(_privateKey, _publicKey);
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
		return BouncyCastleX25519.CalculateAgreement(_privateKey, _peerPublicKey, _sharedSecret);
	}
}
