using CryptoBase.Hpke;
using CryptoBase.SM2;
using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Workloads;

/// <summary>
/// Encrypts a 32-byte message to a public key, or decrypts its ciphertext, once per iteration.
/// </summary>
/// <remarks>
/// A derived class supplies the two operations; the call through them costs nothing next to the public key operations.
/// </remarks>
internal abstract class PublicKeyEncryptionWorkload : Workload
{
	protected const int MessageLength = 32;

	private readonly bool _decrypt;
	private readonly byte[] _plaintext = TestData.Random(MessageLength);
	private byte[] _ciphertext = [];
	private byte[] _newCiphertext = [];
	private byte[] _decrypted = [];

	protected PublicKeyEncryptionWorkload(bool decrypt)
	{
		_decrypt = decrypt;
	}

	public override void Verify()
	{
		SelfTestException.ThrowIfFalse(TryDecrypt(_ciphertext, _decrypted, out int length), "Decryption rejected a valid ciphertext.");
		SelfTestException.ThrowIfNotEqual(_plaintext, _decrypted.AsSpan(0, length), "Decryption recovered a different message.");

		byte[] tampered = [.. _ciphertext];
		tampered[^1] ^= 1;
		SelfTestException.ThrowIfFalse(!TryDecrypt(tampered, _decrypted, out _), "Decryption accepted a tampered ciphertext.");

		byte[] other = new byte[_ciphertext.Length];
		SelfTestException.ThrowIfFalse(Encrypt(_plaintext, other) == other.Length, "Encryption returned a wrong length.");
		SelfTestException.ThrowIfFalse(!other.AsSpan().SequenceEqual(_ciphertext), "Two encryptions gave the same ciphertext.");
	}

	public override void Run(long iterations)
	{
		if (_decrypt)
		{
			DecryptMessages(iterations);
		}
		else
		{
			EncryptMessages(iterations);
		}
	}

	/// <summary>
	/// Encrypts the message once, after the derived constructor has set up the keys.
	/// </summary>
	protected void Initialize(int ciphertextLength)
	{
		_ciphertext = new byte[ciphertextLength];
		_newCiphertext = new byte[ciphertextLength];
		_decrypted = new byte[ciphertextLength];
		Encrypt(_plaintext, _ciphertext);
	}

	/// <returns>The length of the ciphertext.</returns>
	protected abstract int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

	protected abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int bytesWritten);

	private void EncryptMessages(long iterations)
	{
		ReadOnlySpan<byte> plaintext = _plaintext;
		Span<byte> ciphertext = _newCiphertext;

		for (long i = 0; i < iterations; ++i)
		{
			Encrypt(plaintext, ciphertext);
		}
	}

	private void DecryptMessages(long iterations)
	{
		ReadOnlySpan<byte> ciphertext = _ciphertext;
		Span<byte> plaintext = _decrypted;

		for (long i = 0; i < iterations; ++i)
		{
			if (!TryDecrypt(ciphertext, plaintext, out _))
			{
				SelfTestException.Throw("Decryption rejected a valid ciphertext.");
			}
		}
	}
}

/// <summary>
/// SM2 encryption to a public key, as C1 ‖ C3 ‖ C2.
/// </summary>
internal sealed class SM2EncryptionWorkload : PublicKeyEncryptionWorkload
{
	private readonly SM2Key _recipient = SM2Key.GenerateKey();
	private readonly SM2Key _sender;

	public SM2EncryptionWorkload(bool decrypt) : base(decrypt)
	{
		byte[] publicKey = new byte[SM2Key.PublicKeyLength];
		_recipient.ExportPublicKey(publicKey);
		_sender = SM2Key.ImportPublicKey(publicKey);
		Initialize(SM2Key.GetCiphertextLength(MessageLength));
	}

	public override void Dispose()
	{
		_recipient.Dispose();
		_sender.Dispose();
	}

	protected override int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		return _sender.Encrypt(plaintext, ciphertext);
	}

	protected override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int bytesWritten)
	{
		return _recipient.TryDecrypt(ciphertext, plaintext, out bytesWritten);
	}
}

/// <summary>
/// SM9 encryption to the ID of the recipient under the master public key, as C1 ‖ C3 ‖ C2 with the stream cipher of the KDF.
/// </summary>
internal sealed class SM9EncryptionWorkload : PublicKeyEncryptionWorkload
{
	private static readonly byte[] RecipientId = "alice@example.com"u8.ToArray();

	private readonly SM9EncryptionMasterKey _sender;
	private readonly SM9EncryptionKey _recipient;

	public SM9EncryptionWorkload(bool decrypt) : base(decrypt)
	{
		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		byte[] masterPublicKey = new byte[SM9EncryptionMasterKey.PublicKeyLength];
		master.ExportPublicKey(masterPublicKey);

		_recipient = master.ExtractKey(RecipientId);
		_sender = SM9EncryptionMasterKey.ImportPublicKey(masterPublicKey);
		Initialize(SM9EncryptionMasterKey.GetCiphertextLength(MessageLength));
	}

	public override void Dispose()
	{
		_sender.Dispose();
		_recipient.Dispose();
	}

	protected override int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		return _sender.Encrypt(plaintext, ciphertext, RecipientId);
	}

	protected override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int bytesWritten)
	{
		return _recipient.TryDecrypt(ciphertext, plaintext, out bytesWritten);
	}
}

/// <summary>
/// HPKE in the base mode, one message per context: the ciphertext is the encapsulated key followed by the sealed message.
/// </summary>
internal sealed class HpkeWorkload<TKem> : PublicKeyEncryptionWorkload where TKem : class, IHpkeKem<TKem>
{
	private readonly HpkeKdfId _kdf;
	private readonly HpkeAeadId _aead;
	private readonly TKem _recipient = TKem.GenerateKey();
	private readonly TKem _sender;

	public HpkeWorkload(HpkeKdfId kdf, HpkeAeadId aead, bool decrypt) : base(decrypt)
	{
		_kdf = kdf;
		_aead = aead;

		byte[] publicKey = new byte[TKem.EncapsulationKeyLength];
		_recipient.ExportEncapsulationKey(publicKey);
		_sender = TKem.ImportEncapsulationKey(publicKey);
		Initialize(TKem.CiphertextLength + MessageLength + aead.TagSize);
	}

	public override void Dispose()
	{
		_recipient.Dispose();
		_sender.Dispose();
	}

	protected override int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
	{
		int encapsulatedKeyLength = TKem.CiphertextLength;
		using HpkeSenderContext context = HpkeSenderContext.Create(_sender, _kdf, _aead, ciphertext.Slice(0, encapsulatedKeyLength));
		return encapsulatedKeyLength + context.Seal(plaintext, ciphertext.Slice(encapsulatedKeyLength));
	}

	protected override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int bytesWritten)
	{
		int encapsulatedKeyLength = TKem.CiphertextLength;
		bytesWritten = 0;

		if (!HpkeRecipientContext.TryCreate(_recipient, _kdf, _aead, ciphertext.Slice(0, encapsulatedKeyLength), default, out HpkeRecipientContext? context))
		{
			return false;
		}

		using (context)
		{
			ReadOnlySpan<byte> sealedMessage = ciphertext.Slice(encapsulatedKeyLength);
			int length = sealedMessage.Length - _aead.TagSize;

			if (!context.TryOpen(sealedMessage, plaintext.Slice(0, length)))
			{
				return false;
			}

			bytesWritten = length;
			return true;
		}
	}
}
