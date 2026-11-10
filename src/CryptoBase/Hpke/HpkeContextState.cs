using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Macs.Hmac;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hpke;

// The context of RFC 9180, Section 5.2, set up by the key schedule of Section 5.1. The sequence number has 64 bits, as Section 5.2 allows, so its last value is the message limit.
internal struct HpkeContextState
{
	private const int NonceSize = 12;
	private const int TagSize = 16;
	private const int SuiteIdLength = 10;

	// Section 5.1.2 requires 32 bytes of entropy, which no shorter PSK has.
	private const int MinPskLength = 32;

	// GcmMode<AesCipher> or ChaCha20Poly1305Cipher; null for ExportOnly and after Clear.
	private IDisposable? _cipher;
	private InlineArray64<byte> _exporterSecret;

	// The big-endian base nonce: its first 4 bytes, and its last 8, into which the sequence number is XORed.
	private uint _baseNonceHigh;
	private ulong _baseNonceLow;
	private ushort _kemId;

	internal HpkeKdfId Kdf { readonly get; private set; }

	internal HpkeAeadId Aead { readonly get; private set; }

	internal ulong SequenceNumber { readonly get; set; }

	internal static void ValidateSuite(HpkeKdfId kdf, HpkeAeadId aead)
	{
		_ = kdf.HashLength;
		_ = aead.TagSize;
	}

	// VerifyPSKInputs of Section 5.1 for the modes with a PSK; the others take none.
	internal static void ValidatePsk(ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
	{
		if (psk.Length < MinPskLength)
		{
			throw new ArgumentException($"The PSK must be at least {MinPskLength} bytes long.", nameof(psk));
		}

		if (pskId.IsEmpty)
		{
			throw new ArgumentException("The PSK ID must not be empty.", nameof(pskId));
		}
	}

	internal void Initialize(ushort kemId, HpkeMode mode, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
	{
		_kemId = kemId;
		Kdf = kdf;
		Aead = aead;

		switch (kdf)
		{
			case HpkeKdfId.HkdfSha256:
				KeySchedule<Sha256Core>(mode, sharedSecret, info, psk, pskId);
				break;
			case HpkeKdfId.HkdfSha384:
				KeySchedule<Sha384Core>(mode, sharedSecret, info, psk, pskId);
				break;
			default:
				Debug.Assert(kdf is HpkeKdfId.HkdfSha512);
				KeySchedule<Sha512Core>(mode, sharedSecret, info, psk, pskId);
				break;
		}
	}

	[SkipLocalsInit]
	internal int Seal(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> associatedData)
	{
		IDisposable cipher = GetCipher();
		ThrowIfMessageLimitReached();

		if ((uint)ciphertext.Length < (uint)plaintext.Length + TagSize)
		{
			throw new ArgumentOutOfRangeException(nameof(ciphertext), "The ciphertext buffer is shorter than the plaintext and the tag.");
		}

		int length = plaintext.Length + TagSize;
		CipherBufferGuard.SourceDestinationOverlap(plaintext, ciphertext.Slice(0, length), nameof(ciphertext));

		using CryptoBuffer<byte> nonce = new(stackalloc byte[NonceSize]);
		WriteNonce(nonce.Span);
		Span<byte> body = ciphertext.Slice(0, plaintext.Length);
		Span<byte> tag = ciphertext.Slice(plaintext.Length, TagSize);

		if (cipher is GcmMode<AesCipher> gcm)
		{
			gcm.Encrypt(nonce.Span, plaintext, body, tag, associatedData);
		}
		else
		{
			((ChaCha20Poly1305Cipher)cipher).Encrypt(nonce.Span, plaintext, body, tag, associatedData);
		}

		++SequenceNumber;
		return length;
	}

	[SkipLocalsInit]
	internal bool TryOpen(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> associatedData)
	{
		IDisposable cipher = GetCipher();
		ThrowIfMessageLimitReached();

		if (ciphertext.Length < TagSize)
		{
			return false;
		}

		int length = ciphertext.Length - TagSize;
		ArgumentOutOfRangeException.ThrowIfLessThan(plaintext.Length, length, nameof(plaintext));

		Span<byte> output = plaintext.Slice(0, length);
		CipherBufferGuard.SourceDestinationOverlap(ciphertext, output, nameof(plaintext));

		using CryptoBuffer<byte> nonce = new(stackalloc byte[NonceSize]);
		WriteNonce(nonce.Span);
		ReadOnlySpan<byte> body = ciphertext.Slice(0, length);
		ReadOnlySpan<byte> tag = ciphertext.Slice(length);

		bool opened = cipher is GcmMode<AesCipher> gcm
			? gcm.TryDecrypt(nonce.Span, body, tag, output, associatedData)
			: ((ChaCha20Poly1305Cipher)cipher).TryDecrypt(nonce.Span, body, tag, output, associatedData);

		if (opened)
		{
			++SequenceNumber;
		}

		return opened;
	}

	// Context.Export of Section 5.3: LabeledExpand(exporter_secret, "sec", exporter_context, L).
	[SkipLocalsInit]
	internal readonly void Export(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
	{
		int hashLength = Kdf.HashLength;
		ArgumentOutOfRangeException.ThrowIfGreaterThan(destination.Length, 255 * hashLength, nameof(destination));

		// HKDF-Expand derives nothing for L = 0, which Section 5.3 allows.
		if (destination.IsEmpty)
		{
			return;
		}

		Span<byte> suiteId = stackalloc byte[SuiteIdLength];
		WriteSuiteId(suiteId);
		ReadOnlySpan<byte> secret = ((ReadOnlySpan<byte>)_exporterSecret).Slice(0, hashLength);

		switch (Kdf)
		{
			case HpkeKdfId.HkdfSha256:
				HpkeLabels.Expand<Sha256Core>(suiteId, secret, "sec"u8, exporterContext, destination);
				break;
			case HpkeKdfId.HkdfSha384:
				HpkeLabels.Expand<Sha384Core>(suiteId, secret, "sec"u8, exporterContext, destination);
				break;
			default:
				HpkeLabels.Expand<Sha512Core>(suiteId, secret, "sec"u8, exporterContext, destination);
				break;
		}
	}

	internal void Clear()
	{
		_cipher?.Dispose();
		_cipher = null;
		((Span<byte>)_exporterSecret).ZeroMemory();
		_baseNonceHigh = 0;
		_baseNonceLow = 0;
	}

	[SkipLocalsInit]
	private void KeySchedule<TKdf>(HpkeMode mode, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId) where TKdf : unmanaged, IHmacHashCore<TKdf>
	{
		int hashLength = TKdf.HashLength;
		Span<byte> suiteId = stackalloc byte[SuiteIdLength];
		WriteSuiteId(suiteId);

		// key_schedule_context = mode ‖ psk_id_hash ‖ info_hash.
		Span<byte> context = stackalloc byte[1 + 2 * hashLength];
		context[0] = (byte)mode;
		HpkeLabels.Extract<TKdf>(suiteId, default, "psk_id_hash"u8, pskId, context.Slice(1, hashLength));
		HpkeLabels.Extract<TKdf>(suiteId, default, "info_hash"u8, info, context.Slice(1 + hashLength, hashLength));

		using CryptoBuffer<byte> secret = new(stackalloc byte[hashLength]);
		HpkeLabels.Extract<TKdf>(suiteId, sharedSecret, "secret"u8, psk, secret.Span);

		// The three labels expand the same secret, which keys HMAC once for all of them; every output is at most Nh bytes long.
		Unsafe.SkipInit(out HmacState<TKdf> keyed);

		try
		{
			keyed.Initialize(secret.Span, false);
			HpkeLabels.Expand(ref keyed, suiteId, "exp"u8, context, ((Span<byte>)_exporterSecret).Slice(0, hashLength));

			if (Aead is HpkeAeadId.ExportOnly)
			{
				return;
			}

			using CryptoBuffer<byte> key = new(stackalloc byte[Aead.KeySize]);
			using CryptoBuffer<byte> baseNonce = new(stackalloc byte[NonceSize]);
			HpkeLabels.Expand(ref keyed, suiteId, "key"u8, context, key.Span);
			HpkeLabels.Expand(ref keyed, suiteId, "base_nonce"u8, context, baseNonce.Span);
			_baseNonceHigh = BinaryPrimitives.ReadUInt32BigEndian(baseNonce.Span);
			_baseNonceLow = BinaryPrimitives.ReadUInt64BigEndian(baseNonce.Span.Slice(sizeof(uint)));
			_cipher = Aead is HpkeAeadId.ChaCha20Poly1305 ? ChaCha20Poly1305Cipher.Create(key.Span) : GcmMode<AesCipher>.Create(key.Span);
		}
		finally
		{
			keyed.ZeroMemory();
		}
	}

	// suite_id = "HPKE" ‖ I2OSP(kem_id, 2) ‖ I2OSP(kdf_id, 2) ‖ I2OSP(aead_id, 2).
	private readonly void WriteSuiteId(Span<byte> destination)
	{
		"HPKE"u8.CopyTo(destination);
		BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(4), _kemId);
		BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(6), (ushort)Kdf);
		BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(8), (ushort)Aead);
	}

	// ComputeNonce of Section 5.2: the base nonce XOR the sequence number, which fills only the last 8 bytes.
	private readonly void WriteNonce(Span<byte> nonce)
	{
		BinaryPrimitives.WriteUInt32BigEndian(nonce, _baseNonceHigh);
		BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(sizeof(uint)), _baseNonceLow ^ SequenceNumber);
	}

	private readonly IDisposable GetCipher()
	{
		if (_cipher is null)
		{
			ThrowExportOnly();
		}

		return _cipher;
	}

	private readonly void ThrowIfMessageLimitReached()
	{
		if (SequenceNumber is ulong.MaxValue)
		{
			ThrowMessageLimitReached();
		}
	}

	[DoesNotReturn]
	private static void ThrowExportOnly()
	{
		throw new InvalidOperationException("The context has no AEAD: it was set up with HpkeAeadId.ExportOnly.");
	}

	[DoesNotReturn]
	private static void ThrowMessageLimitReached()
	{
		throw new CryptographicException("The context has reached its message limit.");
	}
}
