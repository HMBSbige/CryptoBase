using BenchmarkDotNet.Attributes;
using CryptoBase.SM9;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.Signatures;

// SM9: the operations of the key generation center, signatures, encryption, the key encapsulation, the key exchange and the imports of keys, with IDs of 17 bytes, messages and plaintexts of 32 bytes and keys of 16 bytes. The keys and verifiers are made in the setup and used there until they hold their pairings, lines and tables; a key exchange party is its creation and its derivation with confirmation.
[MemoryDiagnoser]
public class SM9SchemeBenchmark
{
	private static readonly byte[] AliceId = "alice@example.com"u8.ToArray();

	private static readonly byte[] BobId = "bobby@example.com"u8.ToArray();

	private readonly byte[] _message = RandomNumberGenerator.GetBytes(32);
	private readonly byte[] _signatureBuffer = new byte[SM9SignatureKey.SignatureLength];
	private readonly byte[] _ciphertextBuffer = new byte[SM9EncryptionMasterKey.GetCiphertextLength(32)];
	private readonly byte[] _plaintextBuffer = new byte[32];
	private readonly byte[] _encapsulationBuffer = new byte[SM9EncryptionMasterKey.EncapsulationLength];
	private readonly byte[] _keyBuffer = new byte[16];
	private readonly byte[] _confirmation = new byte[SM9KeyExchange.ConfirmationLength];
	private readonly byte[] _peerConfirmation = new byte[SM9KeyExchange.ConfirmationLength];
	private readonly byte[] _privateKeyBuffer = new byte[SM9EncryptionKey.PrivateKeyLength];
	private byte[] _signature = [];
	private byte[] _ciphertext = [];
	private byte[] _encapsulation = [];
	private byte[] _ephemeralA = [];
	private byte[] _ephemeralB = [];
	private byte[] _signaturePublicKey = [];
	private byte[] _encryptionPublicKey = [];
	private byte[] _decryptionKey = [];
	private SM9SignatureMasterKey _signMaster = null!;
	private SM9SignatureMasterKey _verifier = null!;
	private SM9SignatureKey _signer = null!;
	private SM9EncryptionMasterKey _encryptMaster = null!;
	private SM9EncryptionMasterKey _encryptor = null!;
	private SM9EncryptionKey _decryptor = null!;
	private SM9KeyExchangeKey _alice = null!;
	private SM9KeyExchangeKey _bob = null!;

	[GlobalSetup]
	public void Setup()
	{
		_signMaster = SM9SignatureMasterKey.GenerateKey();
		byte[] signPublic = new byte[SM9SignatureMasterKey.PublicKeyLength];
		_signMaster.ExportPublicKey(signPublic);
		_verifier = SM9SignatureMasterKey.ImportPublicKey(signPublic);
		_signaturePublicKey = signPublic;
		_signer = _signMaster.ExtractKey(AliceId);
		_encryptMaster = SM9EncryptionMasterKey.GenerateKey();
		byte[] encryptPublic = new byte[SM9EncryptionMasterKey.PublicKeyLength];
		_encryptMaster.ExportPublicKey(encryptPublic);
		_encryptor = SM9EncryptionMasterKey.ImportPublicKey(encryptPublic);
		_decryptor = _encryptMaster.ExtractKey(BobId);
		_encryptionPublicKey = encryptPublic;
		_decryptionKey = new byte[SM9EncryptionKey.PrivateKeyLength];
		_decryptor.ExportPrivateKey(_decryptionKey);
		_alice = _encryptMaster.ExtractKeyExchangeKey(AliceId);
		_bob = _encryptMaster.ExtractKeyExchangeKey(BobId);

		// The first of each builds the pairings, the second the tables of GT and the later ones those of G1.
		for (int i = 0; i < SM9G1FixedBase.TableThreshold; ++i)
		{
			Sign();
			_signature = [.. _signatureBuffer];

			if (!Verify())
			{
				throw new InvalidOperationException("The signature does not verify.");
			}

			Encrypt();
			_ciphertext = [.. _ciphertextBuffer];

			if (!Decrypt() || !_plaintextBuffer.AsSpan().SequenceEqual(_message))
			{
				throw new InvalidOperationException("The ciphertext does not decrypt.");
			}

			Encapsulate();
			_encapsulation = [.. _encapsulationBuffer];
			byte[] key = [.. _keyBuffer];

			if (!Decapsulate() || !_keyBuffer.AsSpan().SequenceEqual(key))
			{
				throw new InvalidOperationException("The encapsulation does not decapsulate.");
			}
		}

		using SM9KeyExchange initiator = SM9KeyExchange.Create(_alice, BobId, SM9KeyExchangeRole.Initiator);
		using SM9KeyExchange responder = SM9KeyExchange.Create(_bob, AliceId, SM9KeyExchangeRole.Responder);
		_ephemeralA = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
		_ephemeralB = new byte[SM9KeyExchange.EphemeralPublicKeyLength];
		initiator.ExportEphemeralPublicKey(_ephemeralA);
		responder.ExportEphemeralPublicKey(_ephemeralB);
		byte[] keyB = new byte[16];
		byte[] sB = new byte[32];

		if (!responder.TryDeriveKey(_ephemeralA, keyB, sB, _peerConfirmation) || !initiator.TryDeriveKey(_ephemeralB, _keyBuffer, _confirmation, _peerConfirmation) || !_keyBuffer.AsSpan().SequenceEqual(keyB) || !_peerConfirmation.AsSpan().SequenceEqual(sB))
		{
			throw new InvalidOperationException("The parties disagree.");
		}

		for (int i = 0; i < SM9G1FixedBase.TableThreshold; ++i)
		{
			KeyExchangeInitiator();
			KeyExchangeResponder();
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_signMaster.Dispose();
		_verifier.Dispose();
		_signer.Dispose();
		_encryptMaster.Dispose();
		_encryptor.Dispose();
		_decryptor.Dispose();
		_alice.Dispose();
		_bob.Dispose();
	}

	[Benchmark]
	public bool GenerateSignatureMasterKey()
	{
		using SM9SignatureMasterKey key = SM9SignatureMasterKey.GenerateKey();
		return key.HasPrivateKey;
	}

	[Benchmark]
	public bool GenerateEncryptionMasterKey()
	{
		using SM9EncryptionMasterKey key = SM9EncryptionMasterKey.GenerateKey();
		return key.HasPrivateKey;
	}

	[Benchmark]
	public int ExtractSignatureKey()
	{
		using SM9SignatureKey key = _signMaster.ExtractKey(AliceId);
		return key.ExportPrivateKey(_privateKeyBuffer);
	}

	[Benchmark]
	public int ExtractEncryptionKey()
	{
		using SM9EncryptionKey key = _encryptMaster.ExtractKey(BobId);
		return key.ExportPrivateKey(_privateKeyBuffer);
	}

	[Benchmark]
	public int Sign()
	{
		return _signer.Sign(_message, _signatureBuffer);
	}

	[Benchmark]
	public bool Verify()
	{
		return _verifier.Verify(_message, _signature, AliceId);
	}

	[Benchmark]
	public int Encrypt()
	{
		return _encryptor.Encrypt(_message, _ciphertextBuffer, BobId);
	}

	[Benchmark]
	public bool Decrypt()
	{
		return _decryptor.TryDecrypt(_ciphertext, _plaintextBuffer, out _);
	}

	[Benchmark]
	public void Encapsulate()
	{
		_encryptor.Encapsulate(_encapsulationBuffer, _keyBuffer, BobId);
	}

	[Benchmark]
	public bool Decapsulate()
	{
		return _decryptor.TryDecapsulate(_encapsulation, _keyBuffer);
	}

	// The master public key of signatures, Ppub-s of G2, with its checks.
	[Benchmark]
	public bool ImportSignatureMasterPublicKey()
	{
		using SM9SignatureMasterKey key = SM9SignatureMasterKey.ImportPublicKey(_signaturePublicKey);
		return key.HasPrivateKey;
	}

	// A decryption key, deB of G2, with its checks under the master public key.
	[Benchmark]
	public int ImportEncryptionKey()
	{
		using SM9EncryptionKey key = SM9EncryptionKey.ImportPrivateKey(_decryptionKey, _encryptionPublicKey, BobId);
		return key.ExportPrivateKey(_privateKeyBuffer);
	}

	[Benchmark]
	public bool KeyExchangeInitiator()
	{
		using SM9KeyExchange initiator = SM9KeyExchange.Create(_alice, BobId, SM9KeyExchangeRole.Initiator);
		return initiator.TryDeriveKey(_ephemeralB, _keyBuffer, _confirmation, _peerConfirmation);
	}

	[Benchmark]
	public bool KeyExchangeResponder()
	{
		using SM9KeyExchange responder = SM9KeyExchange.Create(_bob, AliceId, SM9KeyExchangeRole.Responder);
		return responder.TryDeriveKey(_ephemeralA, _keyBuffer, _confirmation, _peerConfirmation);
	}
}
