using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.KeyAgreements;
using CryptoBase.KeyAgreements.Ecdh;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.KeyAgreements;

public class EcdhP256Benchmark() : EcdhBenchmark<EcdhP256>(ECCurve.NamedCurves.nistP256, SecObjectIdentifiers.SecP256r1);

public class EcdhP384Benchmark() : EcdhBenchmark<EcdhP384>(ECCurve.NamedCurves.nistP384, SecObjectIdentifiers.SecP384r1);

public class EcdhP521Benchmark() : EcdhBenchmark<EcdhP521>(ECCurve.NamedCurves.nistP521, SecObjectIdentifiers.SecP521r1);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class EcdhBenchmark<T>(ECCurve bclCurve, DerObjectIdentifier bouncyCastleCurve) where T : class, IKeyAgreement<T>
{
	private readonly byte[] _peerPublicKey = new byte[T.PublicKeyLength];
	private readonly byte[] _sharedSecret = new byte[T.SharedSecretLength];
	private readonly SecureRandom _random = new();
	private T _cryptoBase = null!;
	private ECDiffieHellman _bcl = null!;
	private ECDiffieHellman _bclPeer = null!;
	private ECDiffieHellmanPublicKey _bclPeerPublicKey = null!;
	private ECNamedDomainParameters _bouncyCastleDomain = null!;
	private ECKeyPairGenerator _bouncyCastleGenerator = null!;
	private ECDHBasicAgreement _bouncyCastleAgreement = null!;
	private ECPublicKeyParameters _bouncyCastlePeerPublicKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		byte[] privateKey = new byte[T.PrivateKeyLength];
		byte[] publicKey = new byte[T.PublicKeyLength];
		_cryptoBase = T.GenerateKey();
		_cryptoBase.ExportPrivateKey(privateKey);
		_cryptoBase.ExportPublicKey(publicKey);

		using (T peer = T.GenerateKey())
		{
			peer.ExportPublicKey(_peerPublicKey);
		}

		ECParameters bclParameters = UncompressedPoint.ToBcl(bclCurve, publicKey);
		bclParameters.D = privateKey;
		_bcl = ECDiffieHellman.Create(bclParameters);
		_bclPeer = ECDiffieHellman.Create(UncompressedPoint.ToBcl(bclCurve, _peerPublicKey));
		_bclPeerPublicKey = _bclPeer.PublicKey;

		_bouncyCastleDomain = ECNamedDomainParameters.LookupOid(bouncyCastleCurve);
		_bouncyCastleGenerator = new ECKeyPairGenerator();
		_bouncyCastleGenerator.Init(new ECKeyGenerationParameters(bouncyCastleCurve, _random));
		_bouncyCastleAgreement = new ECDHBasicAgreement();
		_bouncyCastleAgreement.Init(new ECPrivateKeyParameters(new BigInteger(1, privateKey), _bouncyCastleDomain));
		_bouncyCastlePeerPublicKey = UncompressedPoint.ToBouncyCastle(_bouncyCastleDomain, _peerPublicKey);

		if (!_bcl.ExportParameters(false).Q.X.AsSpan().SequenceEqual(publicKey.AsSpan(1, T.SharedSecretLength)))
		{
			throw new InvalidOperationException("Benchmark implementations imported different keys.");
		}

		if (!CryptoBaseDeriveSharedSecret())
		{
			throw new InvalidOperationException("The peer public key was rejected.");
		}

		byte[] expected = _sharedSecret.AsSpan().ToArray();
		byte[][] secrets = [BclDeriveSharedSecret(), BouncyCastleDeriveSharedSecret(), BclImportAndDeriveSharedSecret(), BouncyCastleImportAndDeriveSharedSecret()];

		foreach (byte[] secret in secrets)
		{
			if (!secret.AsSpan().SequenceEqual(expected))
			{
				throw new InvalidOperationException("Benchmark implementations derived different shared secrets.");
			}
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_bclPeerPublicKey.Dispose();
		_bclPeer.Dispose();
		_bcl.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseGenerateKey()
	{
		using T key = T.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BclGenerateKey()
	{
		using ECDiffieHellman key = ECDiffieHellman.Create(bclCurve);
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
		return _bouncyCastleGenerator.GenerateKeyPair();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("DeriveSharedSecret")]
	public bool CryptoBaseDeriveSharedSecret()
	{
		return _cryptoBase.TryDeriveSharedSecret(_peerPublicKey, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveSharedSecret")]
	public byte[] BclDeriveSharedSecret()
	{
		return _bcl.DeriveRawSecretAgreement(_bclPeerPublicKey);
	}

	[Benchmark]
	[BenchmarkCategory("DeriveSharedSecret")]
	public byte[] BouncyCastleDeriveSharedSecret()
	{
		return BigIntegers.AsUnsignedByteArray(T.SharedSecretLength, _bouncyCastleAgreement.CalculateAgreement(_bouncyCastlePeerPublicKey));
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPublicKey+DeriveSharedSecret")]
	public bool CryptoBaseImportAndDeriveSharedSecret()
	{
		return _cryptoBase.TryDeriveSharedSecret(_peerPublicKey, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("ImportPublicKey+DeriveSharedSecret")]
	public byte[] BclImportAndDeriveSharedSecret()
	{
		using ECDiffieHellman peer = ECDiffieHellman.Create(UncompressedPoint.ToBcl(bclCurve, _peerPublicKey));
		using ECDiffieHellmanPublicKey peerPublicKey = peer.PublicKey;
		return _bcl.DeriveRawSecretAgreement(peerPublicKey);
	}

	[Benchmark]
	[BenchmarkCategory("ImportPublicKey+DeriveSharedSecret")]
	public byte[] BouncyCastleImportAndDeriveSharedSecret()
	{
		ECPublicKeyParameters peerPublicKey = UncompressedPoint.ToBouncyCastle(_bouncyCastleDomain, _peerPublicKey);
		return BigIntegers.AsUnsignedByteArray(T.SharedSecretLength, _bouncyCastleAgreement.CalculateAgreement(peerPublicKey));
	}
}
