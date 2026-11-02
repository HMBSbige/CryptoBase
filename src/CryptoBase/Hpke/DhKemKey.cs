using CryptoBase.KeyAgreements;

namespace CryptoBase.Hpke;

// DHKEM of RFC 9180, Section 4.1, over the Diffie–Hellman key TDhKey and the KDF of the KEM, TKdf; TKem supplies kem_id. The private seed is the ikm of DeriveKeyPair.
// As with ECKey, keep a key in one writable location and do not copy it. No method that reaches _key is readonly: a readonly one would call TDhKey on a copy.
internal struct DhKemKey<TKem, TDhKey, TKdf>
	where TKem : class, IHpkeKem<TKem>
	where TDhKey : struct, IDiffieHellmanKey<TDhKey>
	where TKdf : unmanaged, IHmacHashCore<TKdf>
{
	private const int SuiteIdLength = 5;

	private TDhKey _key;
	private InlineArray128<byte> _seed;

	internal static int EncapsulationKeyLength => TDhKey.PublicKeyLength;

	internal static int DecapsulationKeyLength => TDhKey.PrivateKeyLength;

	internal static int PrivateSeedLength => TDhKey.PrivateKeyLength;

	internal static int CiphertextLength => TDhKey.PublicKeyLength;

	internal static int SharedSecretLength => TKdf.HashLength;

	internal bool HasPrivateSeed { readonly get; private set; }

	internal bool HasDecapsulationKey => _key.HasPrivateKey;

	[SkipLocalsInit]
	internal void GenerateKey()
	{
		using CryptoBuffer<byte> seed = new(stackalloc byte[PrivateSeedLength]);
		SystemRandom.Fill(seed.Span);
		ImportPrivateSeed(seed.Span);
	}

	internal void ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateSeedLength, nameof(source));
		Debug.Assert(PrivateSeedLength <= Unsafe.SizeOf<InlineArray128<byte>>());

		DeriveKeyPair(source, nameof(source));
		source.CopyTo(_seed);
		HasPrivateSeed = true;
	}

	internal void DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial)
	{
		DeriveKeyPair(inputKeyMaterial, nameof(inputKeyMaterial));
	}

	internal void ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, DecapsulationKeyLength, nameof(source));

		if (!_key.TryImportPrivateKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, EncapsulationKeyLength, nameof(source));

		if (!_key.TryImportPublicKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal int ExportPrivateSeed(Span<byte> destination)
	{
		if (!HasPrivateSeed)
		{
			ThrowHelper.ThrowMissingKey("private seed");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateSeedLength, nameof(destination));

		((ReadOnlySpan<byte>)_seed).Slice(0, PrivateSeedLength).CopyTo(destination);
		return PrivateSeedLength;
	}

	internal int ExportDecapsulationKey(Span<byte> destination)
	{
		if (!_key.HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, DecapsulationKeyLength, nameof(destination));

		return _key.ExportPrivateKey(destination);
	}

	internal int ExportEncapsulationKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EncapsulationKeyLength, nameof(destination));

		return _key.ExportPublicKey(destination);
	}

	// Encap: a random ephemeral key, or, if derive is set, DeriveKeyPair(ephemeralInputKeyMaterial).
	[SkipLocalsInit]
	internal void Encapsulate(bool derive, ReadOnlySpan<byte> ephemeralInputKeyMaterial, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		int length = TDhKey.PublicKeyLength;
		using CryptoBuffer<byte> dh = new(stackalloc byte[TDhKey.SharedSecretLength]);
		Span<byte> kemContext = stackalloc byte[2 * length];
		GenerateEphemeral(derive, ephemeralInputKeyMaterial, kemContext.Slice(0, length), dh.Span);
		_key.ExportPublicKey(kemContext.Slice(length));

		ExtractAndExpand(dh.Span, kemContext, sharedSecret.Slice(0, SharedSecretLength));
		kemContext.Slice(0, length).CopyTo(ciphertext);
	}

	// AuthEncap: dh = DH(skE, pkR) ‖ DH(skS, pkR) and kem_context = enc ‖ pkRm ‖ pkSm.
	[SkipLocalsInit]
	internal void AuthEncapsulate(bool derive, ReadOnlySpan<byte> ephemeralInputKeyMaterial, ref DhKemKey<TKem, TDhKey, TKdf> sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		if (!sender._key.HasPrivateKey)
		{
			throw new ArgumentException("The sender does not hold the decapsulation key.", nameof(sender));
		}

		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		int length = TDhKey.PublicKeyLength;
		int dhLength = TDhKey.SharedSecretLength;
		using CryptoBuffer<byte> dh = new(stackalloc byte[2 * dhLength]);
		Span<byte> kemContext = stackalloc byte[3 * length];
		GenerateEphemeral(derive, ephemeralInputKeyMaterial, kemContext.Slice(0, length), dh.Span.Slice(0, dhLength));
		TDhKey.DeriveSharedSecret(in sender._key, in _key, dh.Span.Slice(dhLength));
		_key.ExportPublicKey(kemContext.Slice(length, length));
		sender._key.ExportPublicKey(kemContext.Slice(2 * length));

		ExtractAndExpand(dh.Span, kemContext, sharedSecret.Slice(0, SharedSecretLength));
		kemContext.Slice(0, length).CopyTo(ciphertext);
	}

	// Decap. Everything that ciphertext overlaps is read before sharedSecret is written.
	[SkipLocalsInit]
	internal bool TryDecapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfCannotDecapsulate(sharedSecret);

		if (ciphertext.Length != CiphertextLength)
		{
			return false;
		}

		int length = TDhKey.PublicKeyLength;
		using CryptoBuffer<byte> dh = new(stackalloc byte[TDhKey.SharedSecretLength]);

		if (!_key.TryDeriveSharedSecret(ciphertext, dh.Span))
		{
			return false;
		}

		Span<byte> kemContext = stackalloc byte[2 * length];
		ciphertext.CopyTo(kemContext);
		_key.ExportPublicKey(kemContext.Slice(length));

		ExtractAndExpand(dh.Span, kemContext, sharedSecret.Slice(0, SharedSecretLength));
		return true;
	}

	// AuthDecap: dh = DH(skR, pkE) ‖ DH(skR, pkS) and kem_context = enc ‖ pkRm ‖ pkSm.
	[SkipLocalsInit]
	internal bool TryAuthDecapsulate(ReadOnlySpan<byte> ciphertext, ref DhKemKey<TKem, TDhKey, TKdf> sender, Span<byte> sharedSecret)
	{
		ThrowIfCannotDecapsulate(sharedSecret);

		if (ciphertext.Length != CiphertextLength)
		{
			return false;
		}

		int length = TDhKey.PublicKeyLength;
		int dhLength = TDhKey.SharedSecretLength;
		using CryptoBuffer<byte> dh = new(stackalloc byte[2 * dhLength]);

		if (!_key.TryDeriveSharedSecret(ciphertext, dh.Span.Slice(0, dhLength)))
		{
			return false;
		}

		TDhKey.DeriveSharedSecret(in _key, in sender._key, dh.Span.Slice(dhLength));
		Span<byte> kemContext = stackalloc byte[3 * length];
		ciphertext.CopyTo(kemContext);
		_key.ExportPublicKey(kemContext.Slice(length, length));
		sender._key.ExportPublicKey(kemContext.Slice(2 * length));

		ExtractAndExpand(dh.Span, kemContext, sharedSecret.Slice(0, SharedSecretLength));
		return true;
	}

	internal void Clear()
	{
		_key.Clear();
		((Span<byte>)_seed).ZeroMemory();
		HasPrivateSeed = false;
	}

	// DeriveKeyPair of RFC 9180, Section 7.1.3, with the KDF of the KEM.
	[SkipLocalsInit]
	private void DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial, string parameterName)
	{
		Span<byte> suiteId = stackalloc byte[SuiteIdLength];
		WriteSuiteId(suiteId);
		using CryptoBuffer<byte> prk = new(stackalloc byte[TKdf.HashLength]);
		using CryptoBuffer<byte> candidate = new(stackalloc byte[TDhKey.PrivateKeyLength]);
		HpkeLabels.Extract<TKdf>(suiteId, default, "dkp_prk"u8, inputKeyMaterial, prk.Span);

		if (TDhKey.IsEveryPrivateKeyValid)
		{
			HpkeLabels.Expand<TKdf>(suiteId, prk.Span, "sk"u8, default, candidate.Span);
			bool imported = _key.TryImportPrivateKey(candidate.Span);
			Debug.Assert(imported);
			return;
		}

		for (int counter = 0; counter <= byte.MaxValue; ++counter)
		{
			byte counterByte = (byte)counter;
			HpkeLabels.Expand<TKdf>(suiteId, prk.Span, "candidate"u8, counterByte.AsReadOnlySpan(), candidate.Span);
			candidate.Span[0] &= TDhKey.PrivateKeyMask;

			if (_key.TryImportPrivateKey(candidate.Span))
			{
				return;
			}
		}

		ThrowHelper.ThrowInvalidKey(parameterName);
	}

	// Writes enc and DH(skE, pkR). A derived ephemeral key goes through a key of its own, which is cleared.
	private void GenerateEphemeral(bool derive, ReadOnlySpan<byte> ephemeralInputKeyMaterial, Span<byte> encapsulatedKey, Span<byte> dh)
	{
		if (!derive)
		{
			TDhKey.GenerateEphemeral(in _key, encapsulatedKey, dh);
			return;
		}

		DhKemKey<TKem, TDhKey, TKdf> ephemeral = default;

		try
		{
			ephemeral.DeriveKeyPair(ephemeralInputKeyMaterial);
			TDhKey.DeriveSharedSecret(in ephemeral._key, in _key, dh);
			ephemeral._key.ExportPublicKey(encapsulatedKey);
		}
		finally
		{
			ephemeral.Clear();
		}
	}

	// ExtractAndExpand of RFC 9180, Section 4.1.
	[SkipLocalsInit]
	private static void ExtractAndExpand(ReadOnlySpan<byte> dh, ReadOnlySpan<byte> kemContext, Span<byte> sharedSecret)
	{
		Span<byte> suiteId = stackalloc byte[SuiteIdLength];
		WriteSuiteId(suiteId);
		using CryptoBuffer<byte> prk = new(stackalloc byte[TKdf.HashLength]);
		HpkeLabels.Extract<TKdf>(suiteId, default, "eae_prk"u8, dh, prk.Span);
		HpkeLabels.Expand<TKdf>(suiteId, prk.Span, "shared_secret"u8, kemContext, sharedSecret);
	}

	// suite_id = "KEM" ‖ I2OSP(kem_id, 2).
	private static void WriteSuiteId(Span<byte> destination)
	{
		"KEM"u8.CopyTo(destination);
		BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(3), TKem.KemId);
	}

	private void ThrowIfCannotEncapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		Debug.Assert(_key.HasPublicKey);

		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, CiphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		if (ByteSpans.Overlaps(ciphertext.Slice(0, CiphertextLength), sharedSecret.Slice(0, SharedSecretLength)))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedSecret));
		}
	}

	private void ThrowIfCannotDecapsulate(Span<byte> sharedSecret)
	{
		if (!_key.HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));
	}
}
