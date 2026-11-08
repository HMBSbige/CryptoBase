using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using CryptoBase.SM2;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using BouncyCastleKeyExchange = Org.BouncyCastle.Crypto.Agreement.SM2KeyExchange;

namespace CryptoBase.Benchmark.Signatures;

// SM2: signatures with the default ID, encryption as C1 ‖ C3 ‖ C2 and the key exchange with confirmation, both parties in one run.
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class SM2Benchmark
{
	private static readonly byte[] Id = "1234567812345678"u8.ToArray();

	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _plaintext = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _signatureBuffer = new byte[SM2Key.MaxSignatureLength];
	private readonly byte[] _ciphertextBuffer = new byte[SM2Key.GetCiphertextLength(32)];
	private readonly byte[] _derCiphertextBuffer = new byte[SM2Key.GetMaxDerCiphertextLength(32)];
	private readonly byte[] _plaintextBuffer = new byte[32];
	private byte[] _signature = [];
	private byte[] _ciphertext = [];
	private byte[] _derCiphertext = [];
	private byte[] _publicKey = [];
	private byte[] _peerPublicKey = [];
	private byte[] _subjectPublicKeyInfo = [];
	private byte[] _privateKey = [];
	private SM2Key _cryptoBase = null!;
	private SM2Key _peer = null!;
	private SM2Key _peerPublic = null!;
	private SM2Key _ownPublic = null!;
	private ECDomainParameters _domain = null!;
	private ECPrivateKeyParameters _bouncyCastlePrivate = null!;
	private ECPublicKeyParameters _bouncyCastlePublic = null!;
	private ECPrivateKeyParameters _bouncyCastlePeerPrivate = null!;
	private ECPublicKeyParameters _bouncyCastlePeerPublic = null!;
	private SecureRandom _random = null!;
	private ECKeyPairGenerator _bouncyCastleGenerator = null!;
	private SM2Signer _bouncyCastleSigner = null!;
	private SM2Signer _bouncyCastleVerifier = null!;
	private SM2Engine _bouncyCastleEncryptor = null!;
	private SM2Engine _bouncyCastleDecryptor = null!;

	[GlobalSetup]
	public void Setup()
	{
		_cryptoBase = SM2Key.GenerateKey();
		_peer = SM2Key.GenerateKey();
		_peerPublicKey = ExportPublicKey(_peer);
		_peerPublic = SM2Key.ImportPublicKey(_peerPublicKey);
		_publicKey = ExportPublicKey(_cryptoBase);
		_ownPublic = SM2Key.ImportPublicKey(_publicKey);
		_subjectPublicKeyInfo = new byte[_cryptoBase.SubjectPublicKeyInfoLength];
		_cryptoBase.ExportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		_privateKey = new byte[SM2Key.PrivateKeyLength];
		_cryptoBase.ExportPrivateKey(_privateKey);

		_domain = ECNamedDomainParameters.LookupOid(GMObjectIdentifiers.sm2p256v1);
		_random = new SecureRandom();
		(_bouncyCastlePrivate, _bouncyCastlePublic) = ToBouncyCastle(_cryptoBase);
		(_bouncyCastlePeerPrivate, _bouncyCastlePeerPublic) = ToBouncyCastle(_peer);
		_bouncyCastleGenerator = new ECKeyPairGenerator();
		_bouncyCastleGenerator.Init(new ECKeyGenerationParameters(_domain, _random));
		_bouncyCastleSigner = new SM2Signer();
		_bouncyCastleSigner.Init(true, new ParametersWithRandom(_bouncyCastlePrivate, _random));
		_bouncyCastleVerifier = new SM2Signer();
		_bouncyCastleVerifier.Init(false, _bouncyCastlePublic);
		_bouncyCastleEncryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
		_bouncyCastleEncryptor.Init(true, new ParametersWithRandom(_bouncyCastlePublic, _random));
		_bouncyCastleDecryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
		_bouncyCastleDecryptor.Init(false, _bouncyCastlePrivate);

		_signature = BouncyCastleSign();

		if (!CryptoBaseVerify() || !BouncyCastleVerify())
		{
			throw new InvalidOperationException("CryptoBase rejected a signature of BouncyCastle.");
		}

		_signature = _signatureBuffer.AsSpan(0, CryptoBaseSign()).ToArray();

		if (!CryptoBaseVerify() || !BouncyCastleVerify() || !CryptoBaseImportAndVerify())
		{
			throw new InvalidOperationException("BouncyCastle rejected a signature of CryptoBase.");
		}

		_ciphertext = BouncyCastleEncrypt();

		if (!CryptoBaseDecrypt() || !_plaintextBuffer.AsSpan().SequenceEqual(_plaintext) || !BouncyCastleDecrypt().AsSpan().SequenceEqual(_plaintext))
		{
			throw new InvalidOperationException("CryptoBase did not decrypt a ciphertext of BouncyCastle.");
		}

		CryptoBaseEncrypt();
		_ciphertext = [.. _ciphertextBuffer];

		if (!BouncyCastleDecrypt().AsSpan().SequenceEqual(_plaintext))
		{
			throw new InvalidOperationException("BouncyCastle did not decrypt a ciphertext of CryptoBase.");
		}

		_derCiphertext = _derCiphertextBuffer.AsSpan(0, CryptoBaseEncryptDer()).ToArray();
		_plaintextBuffer.AsSpan().Clear();

		if (!CryptoBaseDecryptDer() || !_plaintextBuffer.AsSpan().SequenceEqual(_plaintext) || CryptoBaseImportAndEncrypt() != _ciphertextBuffer.Length)
		{
			throw new InvalidOperationException("CryptoBase did not decrypt its own SM2Cipher.");
		}

		CheckKeyExchange();

		if (!CryptoBaseKeyExchange() || !CryptoBaseImportAndKeyExchange() || !CryptoBaseImportPrivateKeyAndKeyExchange())
		{
			throw new InvalidOperationException("CryptoBase failed a key exchange with itself.");
		}

		if (CryptoBaseImportPrivateKeyAndSign() is 0 || !CryptoBaseImportPrivateKeyAndDecrypt())
		{
			throw new InvalidOperationException("CryptoBase failed with an imported private key.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_cryptoBase.Dispose();
		_peer.Dispose();
		_peerPublic.Dispose();
		_ownPublic.Dispose();
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("GenerateKey")]
	public void CryptoBaseGenerateKey()
	{
		using SM2Key key = SM2Key.GenerateKey();
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
		return _cryptoBase.Sign(_message, _signatureBuffer);
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
		return _ownPublic.Verify(_message, _signature);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPrivateKey+Sign")]
	public int CryptoBaseImportPrivateKeyAndSign()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(_privateKey);
		return key.Sign(_message, _signatureBuffer);
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
		using SM2Key key = SM2Key.ImportSubjectPublicKeyInfo(_subjectPublicKeyInfo);
		return key.Verify(_message, _signature);
	}

	[Benchmark]
	[BenchmarkCategory("ImportSubjectPublicKeyInfo+Verify")]
	public bool BouncyCastleImportAndVerify()
	{
		SM2Signer verifier = new();
		verifier.Init(false, PublicKeyFactory.CreateKey(_subjectPublicKeyInfo));
		verifier.BlockUpdate(_message);
		return verifier.VerifySignature(_signature);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Encrypt")]
	public void CryptoBaseEncrypt()
	{
		_ownPublic.Encrypt(_plaintext, _ciphertextBuffer);
	}

	[Benchmark]
	[BenchmarkCategory("Encrypt")]
	public byte[] BouncyCastleEncrypt()
	{
		return _bouncyCastleEncryptor.ProcessBlock(_plaintext, 0, _plaintext.Length);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("EncryptDer")]
	public int CryptoBaseEncryptDer()
	{
		return _ownPublic.EncryptDer(_plaintext, _derCiphertextBuffer);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPublicKey+Encrypt")]
	public int CryptoBaseImportAndEncrypt()
	{
		using SM2Key key = SM2Key.ImportPublicKey(_publicKey);
		return key.Encrypt(_plaintext, _ciphertextBuffer);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("Decrypt")]
	public bool CryptoBaseDecrypt()
	{
		return _cryptoBase.TryDecrypt(_ciphertext, _plaintextBuffer, out _);
	}

	[Benchmark]
	[BenchmarkCategory("Decrypt")]
	public byte[] BouncyCastleDecrypt()
	{
		return _bouncyCastleDecryptor.ProcessBlock(_ciphertext, 0, _ciphertext.Length);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPrivateKey+Decrypt")]
	public bool CryptoBaseImportPrivateKeyAndDecrypt()
	{
		using SM2Key key = SM2Key.ImportPrivateKey(_privateKey);
		return key.TryDecrypt(_ciphertext, _plaintextBuffer, out _);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("DecryptDer")]
	public bool CryptoBaseDecryptDer()
	{
		return _cryptoBase.TryDecryptDer(_derCiphertext, _plaintextBuffer, out _);
	}

	// Both parties: ephemeral keys, the key of 16 bytes and the confirmations.
	[Benchmark(Baseline = true)]
	[BenchmarkCategory("KeyExchange")]
	public bool CryptoBaseKeyExchange()
	{
		Span<byte> ephemeralA = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> ephemeralB = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> key = stackalloc byte[16];
		Span<byte> confirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		Span<byte> peerConfirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		using SM2KeyExchange initiator = SM2KeyExchange.Create(_cryptoBase, Id, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(_peer, Id, SM2KeyExchangeRole.Responder);
		initiator.ExportEphemeralPublicKey(ephemeralA);
		responder.ExportEphemeralPublicKey(ephemeralB);
		return responder.TryDeriveKey(_ownPublic, Id, ephemeralA, key, confirmation, peerConfirmation) & initiator.TryDeriveKey(_peerPublic, Id, ephemeralB, key, confirmation, peerConfirmation);
	}

	// As KeyExchange, each party with the public key of the other imported for it, so without its windows.
	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPublicKey+KeyExchange")]
	public bool CryptoBaseImportAndKeyExchange()
	{
		Span<byte> ephemeralA = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> ephemeralB = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> key = stackalloc byte[16];
		Span<byte> confirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		Span<byte> peerConfirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		using SM2Key ownPublic = SM2Key.ImportPublicKey(_publicKey);
		using SM2Key peerPublic = SM2Key.ImportPublicKey(_peerPublicKey);
		using SM2KeyExchange initiator = SM2KeyExchange.Create(_cryptoBase, Id, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(_peer, Id, SM2KeyExchangeRole.Responder);
		initiator.ExportEphemeralPublicKey(ephemeralA);
		responder.ExportEphemeralPublicKey(ephemeralB);
		return responder.TryDeriveKey(ownPublic, Id, ephemeralA, key, confirmation, peerConfirmation) & initiator.TryDeriveKey(peerPublic, Id, ephemeralB, key, confirmation, peerConfirmation);
	}

	[Benchmark(Baseline = true)]
	[BenchmarkCategory("ImportPrivateKey+KeyExchange")]
	public bool CryptoBaseImportPrivateKeyAndKeyExchange()
	{
		Span<byte> ephemeralA = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> ephemeralB = stackalloc byte[SM2KeyExchange.EphemeralPublicKeyLength];
		Span<byte> key = stackalloc byte[16];
		Span<byte> confirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		Span<byte> peerConfirmation = stackalloc byte[SM2KeyExchange.ConfirmationLength];
		using SM2Key own = SM2Key.ImportPrivateKey(_privateKey);
		using SM2KeyExchange initiator = SM2KeyExchange.Create(own, Id, SM2KeyExchangeRole.Initiator);
		using SM2KeyExchange responder = SM2KeyExchange.Create(_peer, Id, SM2KeyExchangeRole.Responder);
		initiator.ExportEphemeralPublicKey(ephemeralA);
		responder.ExportEphemeralPublicKey(ephemeralB);
		return responder.TryDeriveKey(_ownPublic, Id, ephemeralA, key, confirmation, peerConfirmation) & initiator.TryDeriveKey(_peerPublic, Id, ephemeralB, key, confirmation, peerConfirmation);
	}

	[Benchmark]
	[BenchmarkCategory("KeyExchange")]
	public byte[][] BouncyCastleKeyExchange()
	{
		AsymmetricCipherKeyPair ephemeralA = _bouncyCastleGenerator.GenerateKeyPair();
		AsymmetricCipherKeyPair ephemeralB = _bouncyCastleGenerator.GenerateKeyPair();
		BouncyCastleKeyExchange initiator = new();
		initiator.Init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, _bouncyCastlePrivate, (ECPrivateKeyParameters)ephemeralA.Private), Id));
		BouncyCastleKeyExchange responder = new();
		responder.Init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, _bouncyCastlePeerPrivate, (ECPrivateKeyParameters)ephemeralB.Private), Id));
		byte[][] fromResponder = responder.CalculateKeyWithConfirmation(128, null, new ParametersWithID(new SM2KeyExchangePublicParameters(_bouncyCastlePublic, (ECPublicKeyParameters)ephemeralA.Public), Id));
		byte[][] fromInitiator = initiator.CalculateKeyWithConfirmation(128, fromResponder[1], new ParametersWithID(new SM2KeyExchangePublicParameters(_bouncyCastlePeerPublic, (ECPublicKeyParameters)ephemeralB.Public), Id));
		return fromInitiator;
	}

	private void CheckKeyExchange()
	{
		AsymmetricCipherKeyPair ephemeral = _bouncyCastleGenerator.GenerateKeyPair();
		byte[] bouncyCastleEphemeral = ((ECPublicKeyParameters)ephemeral.Public).Q.GetEncoded(false);
		byte[] cryptoBaseEphemeral = new byte[SM2KeyExchange.EphemeralPublicKeyLength];
		byte[] key = new byte[16];
		byte[] confirmation = new byte[32];
		byte[] peerConfirmation = new byte[32];

		using (SM2KeyExchange initiator = SM2KeyExchange.Create(_cryptoBase, Id, SM2KeyExchangeRole.Initiator))
		{
			initiator.ExportEphemeralPublicKey(cryptoBaseEphemeral);
			BouncyCastleKeyExchange responder = new();
			responder.Init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, _bouncyCastlePeerPrivate, (ECPrivateKeyParameters)ephemeral.Private), Id));
			byte[][] fromResponder = responder.CalculateKeyWithConfirmation(128, null, new ParametersWithID(new SM2KeyExchangePublicParameters(_bouncyCastlePublic, ToPublic(cryptoBaseEphemeral)), Id));

			if (!initiator.TryDeriveKey(_peerPublic, Id, bouncyCastleEphemeral, key, confirmation, peerConfirmation) || !key.AsSpan().SequenceEqual(fromResponder[0]) || !peerConfirmation.AsSpan().SequenceEqual(fromResponder[1]))
			{
				throw new InvalidOperationException("The initiator of CryptoBase and the responder of BouncyCastle disagree.");
			}

			responder.CalculateKeyWithConfirmation(128, null, new ParametersWithID(new SM2KeyExchangePublicParameters(_bouncyCastlePublic, ToPublic(cryptoBaseEphemeral)), Id));
		}

		ephemeral = _bouncyCastleGenerator.GenerateKeyPair();
		bouncyCastleEphemeral = ((ECPublicKeyParameters)ephemeral.Public).Q.GetEncoded(false);

		using (SM2KeyExchange responder = SM2KeyExchange.Create(_peer, Id, SM2KeyExchangeRole.Responder))
		{
			responder.ExportEphemeralPublicKey(cryptoBaseEphemeral);

			if (!responder.TryDeriveKey(_ownPublic, Id, bouncyCastleEphemeral, key, confirmation, peerConfirmation))
			{
				throw new InvalidOperationException("The responder of CryptoBase rejected the ephemeral key of BouncyCastle.");
			}

			BouncyCastleKeyExchange initiator = new();
			initiator.Init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, _bouncyCastlePrivate, (ECPrivateKeyParameters)ephemeral.Private), Id));
			byte[][] fromInitiator = initiator.CalculateKeyWithConfirmation(128, confirmation, new ParametersWithID(new SM2KeyExchangePublicParameters(_bouncyCastlePeerPublic, ToPublic(cryptoBaseEphemeral)), Id));

			if (!key.AsSpan().SequenceEqual(fromInitiator[0]) || !peerConfirmation.AsSpan().SequenceEqual(fromInitiator[1]))
			{
				throw new InvalidOperationException("The initiator of BouncyCastle and the responder of CryptoBase disagree.");
			}
		}
	}

	private (ECPrivateKeyParameters Private, ECPublicKeyParameters Public) ToBouncyCastle(SM2Key key)
	{
		byte[] privateKey = new byte[SM2Key.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		ECPrivateKeyParameters privateParameters = new(new BigInteger(1, privateKey), _domain);
		return (privateParameters, ToPublic(ExportPublicKey(key)));
	}

	private ECPublicKeyParameters ToPublic(byte[] encoded)
	{
		return new ECPublicKeyParameters(_domain.Curve.DecodePoint(encoded), _domain);
	}

	private static byte[] ExportPublicKey(SM2Key key)
	{
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}
}
