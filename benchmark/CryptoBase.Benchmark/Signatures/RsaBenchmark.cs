using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.Abstractions.Signatures;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Rsa;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace CryptoBase.Benchmark.Signatures;

[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class RsaBenchmark
{
	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private byte[] _destination = [];
	private byte[] _signature = [];
	private byte[] _subjectPublicKeyInfo = [];
	private HashAlgorithmName _bclHash;
	private RSASignaturePadding _bclPadding = RSASignaturePadding.Pkcs1;
	private RsaKey _cryptoBase = null!;
	private RSA _bcl = null!;
	private ISigner _bouncyCastleSigner = null!;
	private ISigner _bouncyCastleVerifier = null!;

	[Params(2048, 3072, 4096)]
	public int ModulusBits { get; set; }

	[Params(SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512, SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512)]
	public SignatureAlgorithm Algorithm { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_bcl = RSA.Create(ModulusBits);
		byte[] pkcs8PrivateKey = _bcl.ExportPkcs8PrivateKey();
		_subjectPublicKeyInfo = _bcl.ExportSubjectPublicKeyInfo();
		_cryptoBase = RsaKey.ImportPkcs8PrivateKey(pkcs8PrivateKey);
		_destination = new byte[_cryptoBase.GetMaxSignatureLength(Algorithm)];

		(_bclHash, _bclPadding) = Algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPssSha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
			SignatureAlgorithm.RsaPssSha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
			SignatureAlgorithm.RsaPssSha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
			_ => throw new ArgumentOutOfRangeException(nameof(Algorithm))
		};

		_bouncyCastleSigner = CreateBouncyCastleSigner();
		_bouncyCastleSigner.Init(true, PrivateKeyFactory.CreateKey(pkcs8PrivateKey));
		_bouncyCastleVerifier = CreateBouncyCastleSigner();
		_bouncyCastleVerifier.Init(false, PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));

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
	[BenchmarkCategory("Sign")]
	public int CryptoBaseSign()
	{
		return _cryptoBase.Sign(Algorithm, _message, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Sign")]
	public int BclSign()
	{
		return _bcl.SignData(_message, _destination, _bclHash, _bclPadding);
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
		return _bcl.VerifyData(_message, _signature, _bclHash, _bclPadding);
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
		using RsaKey key = RsaKey.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		return key.Verify(Algorithm, _message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BclImportAndVerify()
	{
		using RSA key = RSA.Create();
		key.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo, out _);
		return key.VerifyData(_message, _signature, _bclHash, _bclPadding);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BouncyCastleImportAndVerify()
	{
		ISigner verifier = CreateBouncyCastleSigner();
		verifier.Init(false, PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));
		verifier.BlockUpdate(_message);
		return verifier.VerifySignature(_signature);
	}

	private ISigner CreateBouncyCastleSigner()
	{
		return Algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => new RsaDigestSigner(new Sha256Digest()),
			SignatureAlgorithm.RsaPkcs1Sha384 => new RsaDigestSigner(new Sha384Digest()),
			SignatureAlgorithm.RsaPkcs1Sha512 => new RsaDigestSigner(new Sha512Digest()),
			SignatureAlgorithm.RsaPssSha256 => new PssSigner(new RsaBlindedEngine(), new Sha256Digest(), 32),
			SignatureAlgorithm.RsaPssSha384 => new PssSigner(new RsaBlindedEngine(), new Sha384Digest(), 48),
			SignatureAlgorithm.RsaPssSha512 => new PssSigner(new RsaBlindedEngine(), new Sha512Digest(), 64),
			_ => throw new ArgumentOutOfRangeException(nameof(Algorithm))
		};
	}
}

[MemoryDiagnoser]
public class RsaGenerateKeyBenchmark
{
	private RsaKeyPairGenerator _bouncyCastleGenerator = null!;

	[Params(2048, 3072)]
	public int ModulusBits { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_bouncyCastleGenerator = new RsaKeyPairGenerator();
		_bouncyCastleGenerator.Init(new RsaKeyGenerationParameters(BouncyCastleBigInteger.ValueOf(65537), new SecureRandom(), ModulusBits, 100));
	}

	[Benchmark(Baseline = true)]
	public void CryptoBaseGenerateKey()
	{
		using RsaKey key = RsaKey.GenerateKey(ModulusBits);
	}

	[Benchmark]
	public byte[] BclGenerateKey()
	{
		using RSA key = RSA.Create(ModulusBits);
		return key.ExportRSAPublicKey();
	}

	[Benchmark]
	public AsymmetricCipherKeyPair BouncyCastleGenerateKey()
	{
		return _bouncyCastleGenerator.GenerateKeyPair();
	}
}

// RSAES-OAEP with SHA-256 for the label and MGF1, and an empty label, of a 32-byte plaintext such as a key.
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class RsaOaepBenchmark
{
	private readonly byte[] _plaintext = RandomNumberGenerator.GetBytes(32);
	private byte[] _destination = [];
	private byte[] _ciphertext = [];
	private RsaKey _cryptoBase = null!;
	private RSA _bcl = null!;
	private OaepEncoding _bouncyCastleEncryptor = null!;
	private OaepEncoding _bouncyCastleDecryptor = null!;

	[Params(2048, 3072, 4096)]
	public int ModulusBits { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_bcl = RSA.Create(ModulusBits);
		byte[] pkcs8PrivateKey = _bcl.ExportPkcs8PrivateKey();
		_cryptoBase = RsaKey.ImportPkcs8PrivateKey(pkcs8PrivateKey);
		_destination = new byte[_cryptoBase.ModulusLength];
		_bouncyCastleEncryptor = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest());
		_bouncyCastleEncryptor.Init(true, PublicKeyFactory.CreateKey(_bcl.ExportSubjectPublicKeyInfo()));
		_bouncyCastleDecryptor = new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest());
		_bouncyCastleDecryptor.Init(false, PrivateKeyFactory.CreateKey(pkcs8PrivateKey));

		Func<byte[]>[] encryptors = [() => _destination.AsSpan(0, CryptoBaseEncrypt()).ToArray(), () => _destination.AsSpan(0, BclEncrypt()).ToArray(), BouncyCastleEncrypt];

		foreach (Func<byte[]> encrypt in encryptors)
		{
			_ciphertext = encrypt();

			if (!CryptoBaseDecrypt() || !_destination.AsSpan(0, _plaintext.Length).SequenceEqual(_plaintext) || !_destination.AsSpan(0, BclDecrypt()).SequenceEqual(_plaintext) || !BouncyCastleDecrypt().AsSpan().SequenceEqual(_plaintext))
			{
				throw new InvalidOperationException("Benchmark implementations rejected each other's ciphertexts.");
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
	[BenchmarkCategory("Encrypt")]
	public int CryptoBaseEncrypt()
	{
		return _cryptoBase.EncryptOaep<Sha256Core>(_plaintext, _destination);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public int BclEncrypt()
	{
		return _bcl.Encrypt(_plaintext, _destination, RSAEncryptionPadding.OaepSHA256);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public byte[] BouncyCastleEncrypt()
	{
		return _bouncyCastleEncryptor.ProcessBlock(_plaintext, 0, _plaintext.Length);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decrypt")]
	public bool CryptoBaseDecrypt()
	{
		return _cryptoBase.TryDecryptOaep<Sha256Core>(_ciphertext, _destination, out _);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public int BclDecrypt()
	{
		return _bcl.Decrypt(_ciphertext, _destination, RSAEncryptionPadding.OaepSHA256);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public byte[] BouncyCastleDecrypt()
	{
		return _bouncyCastleDecryptor.ProcessBlock(_ciphertext, 0, _ciphertext.Length);
	}
}
