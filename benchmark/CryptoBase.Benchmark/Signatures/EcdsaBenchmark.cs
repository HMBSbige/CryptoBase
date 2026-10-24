using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures;

public class EcdsaP256Benchmark() : EcdsaBenchmark<EcdsaP256>(EcdsaP256.GenerateKey, ECCurve.NamedCurves.nistP256, SecObjectIdentifiers.SecP256r1);

public class EcdsaP384Benchmark() : EcdsaBenchmark<EcdsaP384>(EcdsaP384.GenerateKey, ECCurve.NamedCurves.nistP384, SecObjectIdentifiers.SecP384r1);

public class EcdsaP521Benchmark() : EcdsaBenchmark<EcdsaP521>(EcdsaP521.GenerateKey, ECCurve.NamedCurves.nistP521, SecObjectIdentifiers.SecP521r1);

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public abstract class EcdsaBenchmark<T>(Func<T> generateKey, ECCurve bclCurve, DerObjectIdentifier bouncyCastleCurve) where T : class, ISignatureKey<T>
{
	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private readonly SecureRandom _random = new();
	private byte[] _destination = [];
	private byte[] _signature = [];
	private byte[] _subjectPublicKeyInfo = [];
	private HashAlgorithmName _bclHash;
	private T _cryptoBase = null!;
	private ECDsa _bcl = null!;
	private ECKeyPairGenerator _bouncyCastleGenerator = null!;
	private DsaDigestSigner _bouncyCastleSigner = null!;
	private DsaDigestSigner _bouncyCastleVerifier = null!;

	[Params(SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512)]
	public SignatureAlgorithm Algorithm { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = generateKey();
		_destination = new byte[_cryptoBase.GetMaxSignatureLength(Algorithm)];
		_subjectPublicKeyInfo = new byte[_cryptoBase.SubjectPublicKeyInfoLength];
		_cryptoBase.ExportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		byte[] pkcs8PrivateKey = new byte[_cryptoBase.Pkcs8PrivateKeyLength];
		_cryptoBase.ExportPkcs8PrivateKey(pkcs8PrivateKey);

		_bclHash = Algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => HashAlgorithmName.SHA256,
			SignatureAlgorithm.EcdsaSha384 => HashAlgorithmName.SHA384,
			SignatureAlgorithm.EcdsaSha512 => HashAlgorithmName.SHA512,
			_ => throw new ArgumentOutOfRangeException(nameof(Algorithm))
		};
		_bcl = ECDsa.Create();
		_bcl.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);

		_bouncyCastleGenerator = new ECKeyPairGenerator();
		_bouncyCastleGenerator.Init(new ECKeyGenerationParameters(bouncyCastleCurve, _random));
		_bouncyCastleSigner = new DsaDigestSigner(new ECDsaSigner(new HMacDsaKCalculator(CreateDigest())), CreateDigest(), StandardDsaEncoding.Instance);
		_bouncyCastleSigner.Init(true, PrivateKeyFactory.CreateKey(pkcs8PrivateKey));
		_bouncyCastleVerifier = CreateBouncyCastleVerifier(PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));

		Func<byte[]>[] signers = [() => _destination.AsSpan(0, BclSign()).ToArray(), BouncyCastleSign, () => _destination.AsSpan(0, CryptoBaseSign()).ToArray()];
		Func<bool>[] verifiers = [BclVerify, BouncyCastleVerify, CryptoBaseVerify, BclImportAndVerify, BouncyCastleImportAndVerify, CryptoBaseImportAndVerify];

		foreach (Func<byte[]> sign in signers)
		{
			_signature = sign();

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
		_bcl.Dispose();
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
		using ECDsa key = ECDsa.Create(bclCurve);
	}

	[Benchmark]
	[BenchmarkCategory("GenerateKey")]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
		return _bouncyCastleGenerator.GenerateKeyPair();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Sign")]
	public int CryptoBaseSign()
	{
		return _cryptoBase.Sign(Algorithm, _message, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Sign")]
	public int BclSign()
	{
		return _bcl.SignData(_message, _destination, _bclHash, DSASignatureFormat.Rfc3279DerSequence);
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
		return _cryptoBase.Verify(Algorithm, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("Verify")]
	public bool BclVerify()
	{
		return _bcl.VerifyData(_message, _signature, _bclHash, DSASignatureFormat.Rfc3279DerSequence);
	}

	[Benchmark]
	[BenchmarkCategory("Verify")]
	public bool BouncyCastleVerify()
	{
		_bouncyCastleVerifier.BlockUpdate(_message);
		return _bouncyCastleVerifier.VerifySignature(_signature);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool CryptoBaseImportAndVerify()
	{
		using T key = T.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		return key.Verify(Algorithm, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BclImportAndVerify()
	{
		using ECDsa key = ECDsa.Create();
		key.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo, out _);
		return key.VerifyData(_message, _signature, _bclHash, DSASignatureFormat.Rfc3279DerSequence);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BouncyCastleImportAndVerify()
	{
		DsaDigestSigner verifier = CreateBouncyCastleVerifier(PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));
		verifier.BlockUpdate(_message);
		return verifier.VerifySignature(_signature);
	}

	private DsaDigestSigner CreateBouncyCastleVerifier(AsymmetricKeyParameter publicKey)
	{
		DsaDigestSigner verifier = new(new ECDsaSigner(), CreateDigest(), StandardDsaEncoding.Instance);
		verifier.Init(false, publicKey);
		return verifier;
	}

	private IDigest CreateDigest()
	{
		return Algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => new Sha256Digest(),
			SignatureAlgorithm.EcdsaSha384 => new Sha384Digest(),
			SignatureAlgorithm.EcdsaSha512 => new Sha512Digest(),
			_ => throw new ArgumentOutOfRangeException(nameof(Algorithm))
		};
	}
}
