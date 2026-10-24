using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Kems;
using CryptoBase.Benchmark.KeyAgreements;
using CryptoBase.Kems.Hybrid;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kems;

public class SecP256r1MLKem768Benchmark() : EcMLKemBenchmark<SecP256r1MLKem768>(ECCurve.NamedCurves.nistP256, SecObjectIdentifiers.SecP256r1, MLKemAlgorithm.MLKem768, MLKemParameters.ml_kem_768);

public class SecP384r1MLKem1024Benchmark() : EcMLKemBenchmark<SecP384r1MLKem1024>(ECCurve.NamedCurves.nistP384, SecObjectIdentifiers.SecP384r1, MLKemAlgorithm.MLKem1024, MLKemParameters.ml_kem_1024);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class EcMLKemBenchmark<T>(ECCurve bclCurve, DerObjectIdentifier bouncyCastleCurve, MLKemAlgorithm bclAlgorithm, MLKemParameters bouncyCastleParameters) where T : class, IKem<T>
{
	private const int MLKemSeedLength = 64;
	private const int MLKemSharedSecretLength = 32;

	private readonly byte[] _seed = RandomNumberGenerator.GetBytes(T.PrivateSeedLength);
	private readonly byte[] _encapsulationKey = new byte[T.EncapsulationKeyLength];
	private readonly byte[] _ciphertext = new byte[T.CiphertextLength];
	private readonly byte[] _output = new byte[T.CiphertextLength];
	private readonly byte[] _sharedSecret = new byte[T.SharedSecretLength];
	private readonly SecureRandom _random = new();
	private T _cryptoBase = null!;
	private ECDiffieHellman _bclEcdh = null!;
	private ECDiffieHellmanPublicKey _bclPublicKey = null!;
	private MLKem? _bclMLKem;
	private ECNamedDomainParameters _bouncyCastleDomain = null!;
	private ECKeyPairGenerator _bouncyCastleEcGenerator = null!;
	private ECDHBasicAgreement _bouncyCastleAgreement = null!;
	private ECPublicKeyParameters _bouncyCastlePublicKey = null!;
	private MLKemKeyPairGenerator _bouncyCastleMLKemGenerator = null!;
	private MLKemEncapsulator _bouncyCastleEncapsulator = null!;
	private MLKemDecapsulator _bouncyCastleDecapsulator = null!;

	private static int EcLength => T.SharedSecretLength - MLKemSharedSecretLength;

	private static int EcPublicKeyLength => 1 + 2 * EcLength;

	private MLKem BclMLKem => _bclMLKem ?? throw new PlatformNotSupportedException("The platform does not support ML-KEM.");

	[GlobalSetup]
	public void Setup()
	{
		ReadOnlySpan<byte> ecPrivateKey = _seed.AsSpan(0, EcLength);
		ReadOnlySpan<byte> mlKemSeed = _seed.AsSpan(EcLength, MLKemSeedLength);
		_cryptoBase = T.ImportPrivateSeed(_seed);
		_cryptoBase.ExportEncapsulationKey(_encapsulationKey);
		ReadOnlySpan<byte> ecPublicKey = _encapsulationKey.AsSpan(0, EcPublicKeyLength);

		ECParameters bclParameters = UncompressedPoint.ToBcl(bclCurve, ecPublicKey);
		bclParameters.D = ecPrivateKey.ToArray();
		_bclEcdh = ECDiffieHellman.Create(bclParameters);
		_bclPublicKey = _bclEcdh.PublicKey;
		_bclMLKem = MLKem.IsSupported ? MLKem.ImportPrivateSeed(bclAlgorithm, mlKemSeed) : null;

		_bouncyCastleDomain = ECNamedDomainParameters.LookupOid(bouncyCastleCurve);
		_bouncyCastleEcGenerator = new ECKeyPairGenerator();
		_bouncyCastleEcGenerator.Init(new ECKeyGenerationParameters(bouncyCastleCurve, _random));
		_bouncyCastleAgreement = new ECDHBasicAgreement();
		_bouncyCastleAgreement.Init(new ECPrivateKeyParameters(new BigInteger(1, ecPrivateKey), _bouncyCastleDomain));
		_bouncyCastlePublicKey = UncompressedPoint.ToBouncyCastle(_bouncyCastleDomain, ecPublicKey);

		MLKemPrivateKeyParameters bouncyCastleKey = MLKemPrivateKeyParameters.FromSeed(bouncyCastleParameters, mlKemSeed.ToArray());
		_bouncyCastleMLKemGenerator = new MLKemKeyPairGenerator();
		_bouncyCastleMLKemGenerator.Init(new MLKemKeyGenerationParameters(_random, bouncyCastleParameters));
		_bouncyCastleEncapsulator = new MLKemEncapsulator(bouncyCastleParameters);
		_bouncyCastleEncapsulator.Init(new ParametersWithRandom(bouncyCastleKey.GetPublicKey(), _random));
		_bouncyCastleDecapsulator = new MLKemDecapsulator(bouncyCastleParameters);
		_bouncyCastleDecapsulator.Init(bouncyCastleKey);

		if (!_bclEcdh.ExportParameters(false).Q.X.AsSpan().SequenceEqual(ecPublicKey.Slice(1, EcLength))
			|| !bouncyCastleKey.GetPublicKeyEncoded().AsSpan().SequenceEqual(_encapsulationKey.AsSpan(EcPublicKeyLength)))
		{
			throw new InvalidOperationException("Benchmark implementations expanded the seed to different keys.");
		}

		byte[] expected = new byte[T.SharedSecretLength];
		List<Action> encapsulators = [BouncyCastleEncapsulate, CryptoBaseEncapsulate];
		List<Action> decapsulators = [BouncyCastleDecapsulate, CryptoBaseDecapsulate];

		if (_bclMLKem is not null)
		{
			encapsulators.Insert(0, BclEncapsulate);
			decapsulators.Insert(0, BclDecapsulate);
		}

		foreach (Action encapsulate in encapsulators)
		{
			encapsulate();
			_sharedSecret.CopyTo(expected);

			foreach (Action decapsulate in decapsulators)
			{
				_sharedSecret.AsSpan().Clear();
				decapsulate();

				if (!_sharedSecret.AsSpan().SequenceEqual(expected))
				{
					throw new InvalidOperationException("Benchmark implementations produced different shared secrets.");
				}
			}
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_bclPublicKey.Dispose();
		_bclEcdh.Dispose();
		_bclMLKem?.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseGenerateKey()
	{
		using T kem = T.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BclGenerateKey()
	{
		using MLKem kem = MLKem.GenerateKey(bclAlgorithm);
		using ECDiffieHellman ecdh = ECDiffieHellman.Create(bclCurve);
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public (AsymmetricCipherKeyPair, AsymmetricCipherKeyPair) BouncyCastleGenerateKey()
	{
		return (_bouncyCastleEcGenerator.GenerateKeyPair(), _bouncyCastleMLKemGenerator.GenerateKeyPair());
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encapsulate")]
	public void CryptoBaseEncapsulate()
	{
		_cryptoBase.Encapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Encapsulate")]
	public void BclEncapsulate()
	{
		BclEncapsulate(_bclPublicKey, BclMLKem, _ciphertext);
	}

	[Benchmark]
	[BenchmarkCategory("Encapsulate")]
	public void BouncyCastleEncapsulate()
	{
		BouncyCastleEncapsulate(_bouncyCastlePublicKey, _bouncyCastleEncapsulator, _ciphertext);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decapsulate")]
	public void CryptoBaseDecapsulate()
	{
		_cryptoBase.TryDecapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Decapsulate")]
	public void BclDecapsulate()
	{
		MLKem mlKem = BclMLKem;
		using ECDiffieHellman ephemeral = ECDiffieHellman.Create(UncompressedPoint.ToBcl(bclCurve, _ciphertext.AsSpan(0, EcPublicKeyLength)));
		using ECDiffieHellmanPublicKey ephemeralPublicKey = ephemeral.PublicKey;
		_bclEcdh.DeriveRawSecretAgreement(ephemeralPublicKey).CopyTo(_sharedSecret, 0);
		mlKem.Decapsulate(_ciphertext.AsSpan(EcPublicKeyLength), _sharedSecret.AsSpan(EcLength));
	}

	[Benchmark]
	[BenchmarkCategory("Decapsulate")]
	public void BouncyCastleDecapsulate()
	{
		ECPublicKeyParameters ephemeralPublicKey = UncompressedPoint.ToBouncyCastle(_bouncyCastleDomain, _ciphertext.AsSpan(0, EcPublicKeyLength));
		BigIntegers.AsUnsignedByteArray(_bouncyCastleAgreement.CalculateAgreement(ephemeralPublicKey), _sharedSecret.AsSpan(0, EcLength));
		_bouncyCastleDecapsulator.Decapsulate(_ciphertext.AsSpan(EcPublicKeyLength), _sharedSecret.AsSpan(EcLength));
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void CryptoBaseImportAndEncapsulate()
	{
		using T kem = T.ImportEncapsulationKey(_encapsulationKey);
		kem.Encapsulate(_output, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void BclImportAndEncapsulate()
	{
		using MLKem mlKem = MLKem.ImportEncapsulationKey(bclAlgorithm, _encapsulationKey.AsSpan(EcPublicKeyLength));
		using ECDiffieHellman ecdh = ECDiffieHellman.Create(UncompressedPoint.ToBcl(bclCurve, _encapsulationKey.AsSpan(0, EcPublicKeyLength)));
		using ECDiffieHellmanPublicKey publicKey = ecdh.PublicKey;
		BclEncapsulate(publicKey, mlKem, _output);
	}

	[Benchmark]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void BouncyCastleImportAndEncapsulate()
	{
		ECPublicKeyParameters publicKey = UncompressedPoint.ToBouncyCastle(_bouncyCastleDomain, _encapsulationKey.AsSpan(0, EcPublicKeyLength));
		MLKemEncapsulator encapsulator = new(bouncyCastleParameters);
		encapsulator.Init(new ParametersWithRandom(MLKemPublicKeyParameters.FromEncoding(bouncyCastleParameters, _encapsulationKey.AsSpan(EcPublicKeyLength).ToArray()), _random));
		BouncyCastleEncapsulate(publicKey, encapsulator, _output);
	}

	private void BclEncapsulate(ECDiffieHellmanPublicKey publicKey, MLKem mlKem, Span<byte> ciphertext)
	{
		using ECDiffieHellman ephemeral = ECDiffieHellman.Create(bclCurve);
		ECParameters ephemeralParameters = ephemeral.ExportParameters(false);
		ciphertext[0] = 0x04;
		ephemeralParameters.Q.X.CopyTo(ciphertext.Slice(1));
		ephemeralParameters.Q.Y.CopyTo(ciphertext.Slice(1 + EcLength));
		ephemeral.DeriveRawSecretAgreement(publicKey).CopyTo(_sharedSecret, 0);
		mlKem.Encapsulate(ciphertext.Slice(EcPublicKeyLength), _sharedSecret.AsSpan(EcLength));
	}

	private void BouncyCastleEncapsulate(ECPublicKeyParameters publicKey, MLKemEncapsulator encapsulator, Span<byte> ciphertext)
	{
		AsymmetricCipherKeyPair ephemeral = _bouncyCastleEcGenerator.GenerateKeyPair();
		((ECPublicKeyParameters)ephemeral.Public).Q.EncodeTo(false, ciphertext.Slice(0, EcPublicKeyLength));
		ECDHBasicAgreement agreement = new();
		agreement.Init(ephemeral.Private);
		BigIntegers.AsUnsignedByteArray(agreement.CalculateAgreement(publicKey), _sharedSecret.AsSpan(0, EcLength));
		encapsulator.Encapsulate(ciphertext.Slice(EcPublicKeyLength), _sharedSecret.AsSpan(EcLength));
	}
}
