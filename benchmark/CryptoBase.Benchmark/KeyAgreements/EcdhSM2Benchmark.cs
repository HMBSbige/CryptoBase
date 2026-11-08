using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.KeyAgreements.Ecdh;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace CryptoBase.Benchmark.KeyAgreements;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class EcdhSM2Benchmark
{
	private readonly byte[] _peerPublicKey = new byte[EcdhSM2.PublicKeyLength];
	private readonly byte[] _sharedSecret = new byte[EcdhSM2.SharedSecretLength];
	private EcdhSM2 _cryptoBase = null!;
	private ECDomainParameters _domain = null!;
	private ECKeyPairGenerator _bouncyCastleGenerator = null!;
	private ECDHBasicAgreement _bouncyCastleAgreement = null!;
	private ECPublicKeyParameters _bouncyCastlePeerPublicKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		byte[] privateKey = new byte[EcdhSM2.PrivateKeyLength];
		_cryptoBase = EcdhSM2.GenerateKey();
		_cryptoBase.ExportPrivateKey(privateKey);

		using (EcdhSM2 peer = EcdhSM2.GenerateKey())
		{
			peer.ExportPublicKey(_peerPublicKey);
		}

		_domain = ECNamedDomainParameters.LookupOid(GMObjectIdentifiers.sm2p256v1);
		_bouncyCastleGenerator = new ECKeyPairGenerator();
		_bouncyCastleGenerator.Init(new ECKeyGenerationParameters(_domain, new SecureRandom()));
		_bouncyCastleAgreement = new ECDHBasicAgreement();
		_bouncyCastleAgreement.Init(new ECPrivateKeyParameters(new BigInteger(1, privateKey), _domain));
		_bouncyCastlePeerPublicKey = new ECPublicKeyParameters(_domain.Curve.DecodePoint(_peerPublicKey), _domain);

		if (!CryptoBaseDeriveSharedSecret() || !BouncyCastleDeriveSharedSecret().AsSpan().SequenceEqual(_sharedSecret))
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
		using EcdhSM2 key = EcdhSM2.GenerateKey();
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
	public byte[] BouncyCastleDeriveSharedSecret()
	{
		return BigIntegers.AsUnsignedByteArray(EcdhSM2.SharedSecretLength, _bouncyCastleAgreement.CalculateAgreement(_bouncyCastlePeerPublicKey));
	}
}
