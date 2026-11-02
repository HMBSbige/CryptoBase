using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Signatures.EdDsa;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CryptoBase.Benchmark.Signatures;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Ed25519Benchmark
{
	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _privateKey = new byte[Ed25519.PrivateKeyLength];
	private readonly byte[] _publicKey = new byte[Ed25519.PublicKeyLength];
	private readonly byte[] _scratchPrivateKey = new byte[Ed25519.PrivateKeyLength];
	private readonly byte[] _scratchPublicKey = new byte[Ed25519.PublicKeyLength];
	private readonly byte[] _destination = new byte[Ed25519.SignatureLength];
	private readonly SecureRandom _random = new();
	private byte[] _signature = [];
	private Ed25519 _cryptoBase = null!;
	private BouncyCastleEd25519.PublicPoint _bouncyCastlePublicPoint = null!;

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = Ed25519.GenerateKey();
		_cryptoBase.ExportPrivateKey(_privateKey);
		_cryptoBase.ExportPublicKey(_publicKey);
		BouncyCastleEd25519.Precompute();
		_bouncyCastlePublicPoint = BouncyCastleEd25519.ValidatePublicKeyFullExport(_publicKey);

		BouncyCastleEd25519.GeneratePublicKey(_privateKey, _scratchPublicKey);

		if (!_scratchPublicKey.AsSpan().SequenceEqual(_publicKey))
		{
			throw new InvalidOperationException("Benchmark implementations derived different public keys.");
		}

		CryptoBaseSign();
		byte[] expected = _destination.ToArray();
		BouncyCastleSign();

		if (!_destination.AsSpan().SequenceEqual(expected))
		{
			throw new InvalidOperationException("Benchmark implementations gave different signatures.");
		}

		_signature = expected;
		Func<bool>[] verifiers = [CryptoBaseVerify, BouncyCastleVerify, CryptoBaseVerifyCachedKey, BouncyCastleVerifyCachedKey];

		// Three passes, so that the cached instance verifies with and without the table of its public key.
		for (int i = 0; i < 3; ++i)
		{
			foreach (Func<bool> verify in verifiers)
			{
				if (!verify())
				{
					throw new InvalidOperationException("Benchmark implementations rejected each other's signatures.");
				}
			}
		}

		_signature = [.. expected];
		_signature[0] ^= 1;

		foreach (Func<bool> verify in verifiers)
		{
			if (verify())
			{
				throw new InvalidOperationException("Benchmark implementations accepted a tampered signature.");
			}
		}

		_signature = expected;
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
		using Ed25519 key = Ed25519.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BouncyCastleGenerateKey()
	{
		BouncyCastleEd25519.GeneratePrivateKey(_random, _scratchPrivateKey);
		BouncyCastleEd25519.GeneratePublicKey(_scratchPrivateKey, _scratchPublicKey);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Sign")]
	public int CryptoBaseSign()
	{
		return _cryptoBase.Sign(_message, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Sign")]
	public void BouncyCastleSign()
	{
		BouncyCastleEd25519.Sign(sk: _privateKey, pk: _publicKey, m: _message, sig: _destination);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPublicKey+Verify")]
	public bool CryptoBaseVerify()
	{
		using Ed25519 key = Ed25519.ImportPublicKey(_publicKey);
		return key.Verify(_message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportPublicKey+Verify")]
	public bool BouncyCastleVerify()
	{
		return BouncyCastleEd25519.Verify(sig: _signature, pk: _publicKey, m: _message);
	}

	// The global setup has verified with _cryptoBase more than once, so its table is built.
	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Verify")]
	public bool CryptoBaseVerifyCachedKey()
	{
		return _cryptoBase.Verify(_message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("Verify")]
	public bool BouncyCastleVerifyCachedKey()
	{
		return BouncyCastleEd25519.Verify(_signature, _bouncyCastlePublicPoint, _message);
	}
}
