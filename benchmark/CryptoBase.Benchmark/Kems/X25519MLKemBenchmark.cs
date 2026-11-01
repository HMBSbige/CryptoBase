using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Kems.Hybrid;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace CryptoBase.Benchmark.Kems;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class X25519MLKem768Benchmark
{
	private const int MLKemSeedLength = 64;
	private const int MLKemEncapsulationKeyLength = 1184;
	private const int MLKemCiphertextLength = 1088;
	private const int MLKemSharedSecretLength = 32;
	private const int X25519Length = 32;

	private readonly byte[] _seed = RandomNumberGenerator.GetBytes(X25519MLKem768.PrivateSeedLength);
	private readonly byte[] _encapsulationKey = new byte[X25519MLKem768.EncapsulationKeyLength];
	private readonly byte[] _ciphertext = new byte[X25519MLKem768.CiphertextLength];
	private readonly byte[] _output = new byte[X25519MLKem768.CiphertextLength];
	private readonly byte[] _sharedSecret = new byte[X25519MLKem768.SharedSecretLength];
	private readonly byte[] _secP256r1EncapsulationKey = new byte[SecP256r1MLKem768.EncapsulationKeyLength];
	private readonly byte[] _secP256r1Ciphertext = new byte[SecP256r1MLKem768.CiphertextLength];
	private readonly byte[] _secP256r1Output = new byte[SecP256r1MLKem768.CiphertextLength];
	private readonly byte[] _ephemeral = new byte[X25519Length];
	private readonly SecureRandom _random = new();
	private X25519MLKem768 _cryptoBase = null!;
	private SecP256r1MLKem768 _secP256r1 = null!;
	private MLKemKeyPairGenerator _bouncyCastleGenerator = null!;
	private MLKemEncapsulator _bouncyCastleEncapsulator = null!;
	private MLKemDecapsulator _bouncyCastleDecapsulator = null!;

	private ReadOnlySpan<byte> X25519PrivateKey => _seed.AsSpan(MLKemSeedLength);

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = X25519MLKem768.ImportPrivateSeed(_seed);
		_cryptoBase.ExportEncapsulationKey(_encapsulationKey);
		_secP256r1 = SecP256r1MLKem768.GenerateKey();
		_secP256r1.ExportEncapsulationKey(_secP256r1EncapsulationKey);
		_secP256r1.Encapsulate(_secP256r1Ciphertext, _sharedSecret);

		MLKemPrivateKeyParameters bouncyCastleKey = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, _seed.AsSpan(0, MLKemSeedLength).ToArray());
		_bouncyCastleGenerator = new MLKemKeyPairGenerator();
		_bouncyCastleGenerator.Init(new MLKemKeyGenerationParameters(_random, MLKemParameters.ml_kem_768));
		_bouncyCastleEncapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
		_bouncyCastleEncapsulator.Init(new ParametersWithRandom(bouncyCastleKey.GetPublicKey(), _random));
		_bouncyCastleDecapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
		_bouncyCastleDecapsulator.Init(bouncyCastleKey);
		BouncyCastleX25519.Precompute();

		byte[] x25519PublicKey = new byte[X25519Length];
		BouncyCastleX25519.GeneratePublicKey(X25519PrivateKey, x25519PublicKey);

		if (!bouncyCastleKey.GetPublicKeyEncoded().AsSpan().SequenceEqual(_encapsulationKey.AsSpan(0, MLKemEncapsulationKeyLength)) || !x25519PublicKey.AsSpan().SequenceEqual(_encapsulationKey.AsSpan(MLKemEncapsulationKeyLength)))
		{
			throw new InvalidOperationException("Benchmark implementations expanded the seed to different keys.");
		}

		KemCrossCheck.Run(_sharedSecret, [BouncyCastleEncapsulate, CryptoBaseEncapsulate], [BouncyCastleDecapsulate, CryptoBaseDecapsulate]);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_secP256r1.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseGenerateKey()
	{
		using X25519MLKem768 kem = X25519MLKem768.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseSecP256r1GenerateKey()
	{
		using SecP256r1MLKem768 kem = SecP256r1MLKem768.GenerateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
		BouncyCastleX25519.GeneratePrivateKey(_random, _ephemeral);
		BouncyCastleX25519.GeneratePublicKey(_ephemeral, _output.AsSpan(0, X25519Length));
		return _bouncyCastleGenerator.GenerateKeyPair();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encapsulate")]
	public void CryptoBaseEncapsulate()
	{
		_cryptoBase.Encapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Encapsulate")]
	public void CryptoBaseSecP256r1Encapsulate()
	{
		_secP256r1.Encapsulate(_secP256r1Output, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Encapsulate")]
	public void BouncyCastleEncapsulate()
	{
		BouncyCastleEncapsulate(_bouncyCastleEncapsulator, _ciphertext);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decapsulate")]
	public void CryptoBaseDecapsulate()
	{
		_cryptoBase.TryDecapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Decapsulate")]
	public void CryptoBaseSecP256r1Decapsulate()
	{
		_secP256r1.TryDecapsulate(_secP256r1Ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Decapsulate")]
	public void BouncyCastleDecapsulate()
	{
		_bouncyCastleDecapsulator.Decapsulate(_ciphertext.AsSpan(0, MLKemCiphertextLength), _sharedSecret.AsSpan(0, MLKemSharedSecretLength));

		if (!BouncyCastleX25519.CalculateAgreement(X25519PrivateKey, _ciphertext.AsSpan(MLKemCiphertextLength), _sharedSecret.AsSpan(MLKemSharedSecretLength)))
		{
			throw new CryptographicException("The X25519 shared secret is all zeros.");
		}
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void CryptoBaseImportAndEncapsulate()
	{
		using X25519MLKem768 kem = X25519MLKem768.ImportEncapsulationKey(_encapsulationKey);
		kem.Encapsulate(_output, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void CryptoBaseSecP256r1ImportAndEncapsulate()
	{
		using SecP256r1MLKem768 kem = SecP256r1MLKem768.ImportEncapsulationKey(_secP256r1EncapsulationKey);
		kem.Encapsulate(_secP256r1Output, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void BouncyCastleImportAndEncapsulate()
	{
		MLKemEncapsulator encapsulator = new(MLKemParameters.ml_kem_768);
		encapsulator.Init(new ParametersWithRandom(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, _encapsulationKey.AsSpan(0, MLKemEncapsulationKeyLength).ToArray()), _random));
		BouncyCastleEncapsulate(encapsulator, _output);
	}

	private void BouncyCastleEncapsulate(MLKemEncapsulator encapsulator, Span<byte> ciphertext)
	{
		encapsulator.Encapsulate(ciphertext.Slice(0, MLKemCiphertextLength), _sharedSecret.AsSpan(0, MLKemSharedSecretLength));
		BouncyCastleX25519.GeneratePrivateKey(_random, _ephemeral);
		BouncyCastleX25519.GeneratePublicKey(_ephemeral, ciphertext.Slice(MLKemCiphertextLength, X25519Length));

		if (!BouncyCastleX25519.CalculateAgreement(_ephemeral, _encapsulationKey.AsSpan(MLKemEncapsulationKeyLength), _sharedSecret.AsSpan(MLKemSharedSecretLength)))
		{
			throw new CryptographicException("The X25519 shared secret is all zeros.");
		}
	}
}
