using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.MLDsa;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures;

public class MLDsa44Benchmark() : MLDsaBenchmark<MLDsa44>(SignatureScheme.MLDsa44, MLDsa44.GenerateKey, seed => MLDsa44.ImportPrivateSeed(seed), MLDsaAlgorithm.MLDsa44, MLDsaParameters.ml_dsa_44);

public class MLDsa65Benchmark() : MLDsaBenchmark<MLDsa65>(SignatureScheme.MLDsa65, MLDsa65.GenerateKey, seed => MLDsa65.ImportPrivateSeed(seed), MLDsaAlgorithm.MLDsa65, MLDsaParameters.ml_dsa_65);

public class MLDsa87Benchmark() : MLDsaBenchmark<MLDsa87>(SignatureScheme.MLDsa87, MLDsa87.GenerateKey, seed => MLDsa87.ImportPrivateSeed(seed), MLDsaAlgorithm.MLDsa87, MLDsaParameters.ml_dsa_87);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class MLDsaBenchmark<T>(SignatureScheme scheme, Func<T> generateKey, Func<byte[], T> importPrivateSeed, MLDsaAlgorithm bclAlgorithm, MLDsaParameters bouncyCastleParameters) where T : class, ISignatureKey<T>
{
	// Every parameter set has a 32-byte seed.
	private readonly byte[] _seed = RandomNumberGenerator.GetBytes(MLDsa44.PrivateSeedLength);
	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private readonly SecureRandom _random = new();
	private byte[] _signature = [];
	private byte[] _subjectPublicKeyInfo = [];
	private T _cryptoBase = null!;
	private MLDsa? _bcl;
	private MLDsaKeyPairGenerator _bouncyCastleGenerator = null!;
	private MLDsaSigner _bouncyCastleSigner = null!;
	private MLDsaSigner _bouncyCastleVerifier = null!;

	private MLDsa Bcl => _bcl ?? throw new PlatformNotSupportedException("The platform does not support ML-DSA.");

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = importPrivateSeed(_seed);
		_signature = new byte[_cryptoBase.GetMaxSignatureLength(scheme)];
		_subjectPublicKeyInfo = new byte[_cryptoBase.SubjectPublicKeyInfoLength];
		_cryptoBase.ExportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		_bcl = MLDsa.IsSupported ? MLDsa.ImportMLDsaPrivateSeed(bclAlgorithm, _seed) : null;

		MLDsaPrivateKeyParameters bouncyCastleKey = MLDsaPrivateKeyParameters.FromSeed(bouncyCastleParameters, _seed);
		_bouncyCastleGenerator = new MLDsaKeyPairGenerator();
		_bouncyCastleGenerator.Init(new MLDsaKeyGenerationParameters(_random, bouncyCastleParameters));
		_bouncyCastleSigner = new MLDsaSigner(bouncyCastleParameters, false);
		_bouncyCastleSigner.Init(true, new ParametersWithRandom(bouncyCastleKey, _random));
		_bouncyCastleVerifier = new MLDsaSigner(bouncyCastleParameters, false);
		_bouncyCastleVerifier.Init(false, bouncyCastleKey.GetPublicKey());

		// Cross-checks the implementations, leaving a signature by the last signer for the verification benchmarks.
		List<Action> signers = [() => BouncyCastleSign().CopyTo(_signature, 0), CryptoBaseSign];
		List<Func<bool>> verifiers = [BouncyCastleVerify, CryptoBaseVerify, BouncyCastleImportAndVerify, CryptoBaseImportAndVerify];

		if (_bcl is not null)
		{
			signers.Insert(0, BclSign);
			verifiers.Insert(0, BclVerify);
			verifiers.Insert(0, BclImportAndVerify);
		}

		foreach (Action sign in signers)
		{
			_signature.AsSpan().Clear();
			sign();

			foreach (Func<bool> verify in verifiers)
			{
				if (!verify())
				{
					throw new InvalidOperationException("Benchmark implementations rejected each other's signatures.");
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
		using T key = generateKey();
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public void BclGenerateKey()
	{
		using MLDsa key = MLDsa.GenerateKey(bclAlgorithm);
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
		return _bouncyCastleGenerator.GenerateKeyPair();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Sign")]
	public void CryptoBaseSign()
	{
		_cryptoBase.Sign(scheme, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("Sign")]
	public void BclSign()
	{
		Bcl.SignData(_message, _signature.AsSpan());
	}

	[Benchmark]
	[BenchmarkCategory("Sign")]
	public byte[] BouncyCastleSign()
	{
		_bouncyCastleSigner.BlockUpdate(_message);
		return _bouncyCastleSigner.GenerateSignature();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Verify")]
	public bool CryptoBaseVerify()
	{
		return _cryptoBase.Verify(scheme, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("Verify")]
	public bool BclVerify()
	{
		return Bcl.VerifyData(_message.AsSpan(), _signature);
	}

	[Benchmark]
	[BenchmarkCategory("Verify")]
	public bool BouncyCastleVerify()
	{
		_bouncyCastleVerifier.BlockUpdate(_message);
		return _bouncyCastleVerifier.VerifySignature(_signature);
	}

	// A fresh public key for every verification, as a TLS client that receives the server's certificate in each handshake does.
	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool CryptoBaseImportAndVerify()
	{
		using T key = T.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		return key.Verify(scheme, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BclImportAndVerify()
	{
#pragma warning disable SYSLIB5006
		using MLDsa key = MLDsa.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
#pragma warning restore SYSLIB5006
		return key.VerifyData(_message.AsSpan(), _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BouncyCastleImportAndVerify()
	{
		MLDsaSigner verifier = new(bouncyCastleParameters, false);
		verifier.Init(false, PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));
		verifier.BlockUpdate(_message);
		return verifier.VerifySignature(_signature);
	}
}
