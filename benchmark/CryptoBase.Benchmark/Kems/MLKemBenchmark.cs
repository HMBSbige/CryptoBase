using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Kems;
using CryptoBase.Kems.MLKem;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Kems;

public class MLKem512Benchmark() : MLKemBenchmark<MLKem512>(MLKemAlgorithm.MLKem512, MLKemParameters.ml_kem_512);

public class MLKem768Benchmark() : MLKemBenchmark<MLKem768>(MLKemAlgorithm.MLKem768, MLKemParameters.ml_kem_768);

public class MLKem1024Benchmark() : MLKemBenchmark<MLKem1024>(MLKemAlgorithm.MLKem1024, MLKemParameters.ml_kem_1024);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class MLKemBenchmark<T>(MLKemAlgorithm bclAlgorithm, MLKemParameters bouncyCastleParameters) where T : class, IKem<T>
{
	private readonly byte[] _seed = RandomNumberGenerator.GetBytes(T.PrivateSeedLength);
	private readonly byte[] _encapsulationKey = new byte[T.EncapsulationKeyLength];
	private readonly byte[] _ciphertext = new byte[T.CiphertextLength];
	private readonly byte[] _output = new byte[T.CiphertextLength];
	private readonly byte[] _sharedSecret = new byte[T.SharedSecretLength];
	private readonly SecureRandom _random = new();
	private T _cryptoBase = null!;
	private MLKem? _bcl;
	private MLKemKeyPairGenerator _bouncyCastleGenerator = null!;
	private MLKemEncapsulator _bouncyCastleEncapsulator = null!;
	private MLKemDecapsulator _bouncyCastleDecapsulator = null!;

	private MLKem Bcl => _bcl ?? throw new PlatformNotSupportedException("The platform does not support ML-KEM.");

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = T.ImportPrivateSeed(_seed);
		_cryptoBase.ExportEncapsulationKey(_encapsulationKey);
		_bcl = MLKem.IsSupported ? MLKem.ImportPrivateSeed(bclAlgorithm, _seed) : null;

		MLKemPrivateKeyParameters bouncyCastleKey = MLKemPrivateKeyParameters.FromSeed(bouncyCastleParameters, _seed);
		_bouncyCastleGenerator = new MLKemKeyPairGenerator();
		_bouncyCastleGenerator.Init(new MLKemKeyGenerationParameters(_random, bouncyCastleParameters));
		_bouncyCastleEncapsulator = new MLKemEncapsulator(bouncyCastleParameters);
		_bouncyCastleEncapsulator.Init(new ParametersWithRandom(bouncyCastleKey.GetPublicKey(), _random));
		_bouncyCastleDecapsulator = new MLKemDecapsulator(bouncyCastleParameters);
		_bouncyCastleDecapsulator.Init(bouncyCastleKey);

		if (!bouncyCastleKey.GetPublicKeyEncoded().AsSpan().SequenceEqual(_encapsulationKey))
		{
			throw new InvalidOperationException("Benchmark implementations expanded the seed to different keys.");
		}

		// Cross-checks the implementations, leaving the last ciphertext for the decapsulation benchmarks.
		byte[] expected = new byte[T.SharedSecretLength];
		List<Action> encapsulators = [BouncyCastleEncapsulate, CryptoBaseEncapsulate];
		List<Action> decapsulators = [BouncyCastleDecapsulate, CryptoBaseDecapsulate];

		if (_bcl is not null)
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
		_bcl?.Dispose();
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
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
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
	public void BclEncapsulate()
	{
		Bcl.Encapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Encapsulate")]
	public void BouncyCastleEncapsulate()
	{
		_bouncyCastleEncapsulator.Encapsulate(_ciphertext, _sharedSecret);
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
		Bcl.Decapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("Decapsulate")]
	public void BouncyCastleDecapsulate()
	{
		_bouncyCastleDecapsulator.Decapsulate(_ciphertext, _sharedSecret);
	}

	// A fresh encapsulation key for every encapsulation, as a peer that receives one per handshake does.
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
		using MLKem kem = MLKem.ImportEncapsulationKey(bclAlgorithm, _encapsulationKey);
		kem.Encapsulate(_output, _sharedSecret);
	}

	[Benchmark]
	[BenchmarkCategory("ImportEncapsulationKey+Encapsulate")]
	public void BouncyCastleImportAndEncapsulate()
	{
		MLKemEncapsulator encapsulator = new(bouncyCastleParameters);
		encapsulator.Init(new ParametersWithRandom(MLKemPublicKeyParameters.FromEncoding(bouncyCastleParameters, _encapsulationKey), _random));
		encapsulator.Encapsulate(_output, _sharedSecret);
	}
}
