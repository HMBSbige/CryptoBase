using CryptoBase.EllipticCurves;
using CryptoBase.Kems.MLKem;

namespace CryptoBase.Kems.Hybrid;

// As with ECKey and MLKemKey, keep a key in one writable location and do not copy it.
internal struct ECMLKemKey<TCurve, TField, TOrder, TParameters>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
	where TParameters : struct, IMLKemParameters
{
	private ECKey<TCurve, TField, TOrder> _ecKey;
	private MLKemKey<TParameters> _mlKemKey;

	internal static int EncapsulationKeyLength => ECPublicKeyLength + MLKemKey<TParameters>.EncapsulationKeyLength;

	internal static int DecapsulationKeyLength => ECPrivateKeyLength + MLKemKey<TParameters>.DecapsulationKeyLength;

	internal static int PrivateSeedLength => ECPrivateKeyLength + MLKemKey<TParameters>.PrivateSeedLength;

	internal static int CiphertextLength => ECPublicKeyLength + MLKemKey<TParameters>.CiphertextLength;

	internal static int SharedSecretLength => ECSharedSecretLength + MLKemKey<TParameters>.SharedSecretLength;

	// The elliptic curve private key is held whenever the ML-KEM decapsulation key is.
	internal readonly bool HasPrivateSeed => _mlKemKey.HasPrivateSeed;

	internal readonly bool HasDecapsulationKey => _mlKemKey.HasDecapsulationKey;

	private static int ECPrivateKeyLength => ECKey<TCurve, TField, TOrder>.PrivateKeyLength;

	private static int ECPublicKeyLength => ECKey<TCurve, TField, TOrder>.PublicKeyLength;

	private static int ECSharedSecretLength => ECKey<TCurve, TField, TOrder>.SharedSecretLength;

	// Here and in the two private imports, the ML-KEM part goes first: MLKemKey throws without keeping any of the new key, so only a failure of the elliptic curve part, which keeps no new d either, needs the ML-KEM part cleared.
	internal void GenerateKey()
	{
		_mlKemKey.GenerateKey();

		try
		{
			_ecKey.GenerateKey();
		}
		catch
		{
			_mlKemKey.Clear();
			throw;
		}
	}

	internal void ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateSeedLength, nameof(source));

		_mlKemKey.ImportPrivateSeed(source.Slice(ECPrivateKeyLength));

		if (!_ecKey.TryImportPrivateKey(source.Slice(0, ECPrivateKeyLength)))
		{
			_mlKemKey.Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, DecapsulationKeyLength, nameof(source));

		_mlKemKey.ImportDecapsulationKey(source.Slice(ECPrivateKeyLength));

		if (!_ecKey.TryImportPrivateKey(source.Slice(0, ECPrivateKeyLength)))
		{
			_mlKemKey.Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, EncapsulationKeyLength, nameof(source));

		if (!_ecKey.TryImportPublicKey(source.Slice(0, ECPublicKeyLength)))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		_mlKemKey.ImportEncapsulationKey(source.Slice(ECPublicKeyLength));
	}

	internal readonly int ExportPrivateSeed(Span<byte> destination)
	{
		if (!HasPrivateSeed)
		{
			ThrowHelper.ThrowMissingKey("private seed");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateSeedLength, nameof(destination));

		_ecKey.ExportPrivateKey(destination);
		_mlKemKey.ExportPrivateSeed(destination.Slice(ECPrivateKeyLength));
		return PrivateSeedLength;
	}

	internal int ExportDecapsulationKey(Span<byte> destination)
	{
		if (!HasDecapsulationKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, DecapsulationKeyLength, nameof(destination));

		_ecKey.ExportPrivateKey(destination);
		_mlKemKey.ExportDecapsulationKey(destination.Slice(ECPrivateKeyLength));
		return DecapsulationKeyLength;
	}

	internal readonly int ExportEncapsulationKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EncapsulationKeyLength, nameof(destination));

		_ecKey.ExportPublicKey(destination);
		_mlKemKey.ExportEncapsulationKey(destination.Slice(ECPublicKeyLength));
		return EncapsulationKeyLength;
	}

	internal void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		FieldElement<TOrder> ephemeral = default;

		try
		{
			ECKey<TCurve, TField, TOrder>.GeneratePrivateScalar(SystemRandom.Fill, out ephemeral);
			_mlKemKey.Encapsulate(ciphertext.Slice(ECPublicKeyLength), sharedSecret.Slice(ECSharedSecretLength));
			WriteECParts(in ephemeral, ciphertext, sharedSecret);
		}
		finally
		{
			ephemeral.ZeroMemory();
		}
	}

	internal void Encapsulate(ReadOnlySpan<byte> ephemeralPrivateKey, ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		FieldElement<TOrder> ephemeral = default;

		try
		{
			if (!FieldElement<TOrder>.TryImportNonzero(ephemeralPrivateKey, out ephemeral))
			{
				ThrowHelper.ThrowInvalidKey(nameof(ephemeralPrivateKey));
			}

			_mlKemKey.Encapsulate(message, ciphertext.Slice(ECPublicKeyLength), sharedSecret.Slice(ECSharedSecretLength));
			WriteECParts(in ephemeral, ciphertext, sharedSecret);
		}
		finally
		{
			ephemeral.ZeroMemory();
		}
	}

	// Both parts are computed before sharedSecret is written, since ciphertext may overlap it.
	[SkipLocalsInit]
	internal bool TryDecapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		if (!HasDecapsulationKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		if (ciphertext.Length != CiphertextLength)
		{
			return false;
		}

		using CryptoBuffer<byte> secret = new(stackalloc byte[SharedSecretLength]);

		// d·R cannot be the point at infinity, so this fails only if R is not a point on the curve.
		if (!_ecKey.TryDeriveSharedSecret(ciphertext.Slice(0, ECPublicKeyLength), secret.Span))
		{
			return false;
		}

		bool decapsulated = _mlKemKey.TryDecapsulate(ciphertext.Slice(ECPublicKeyLength), secret.Span.Slice(ECSharedSecretLength));
		Debug.Assert(decapsulated);

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	internal void Clear()
	{
		_ecKey.Clear();
		_mlKemKey.Clear();
	}

	// The ML-KEM part checks for its own key; the elliptic curve point is read directly, so it is checked here.
	private readonly void ThrowIfCannotEncapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		if (!_ecKey.HasPublicKey)
		{
			ThrowHelper.ThrowMissingKey("encapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, CiphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		if (ciphertext.Slice(0, CiphertextLength).Overlaps(sharedSecret.Slice(0, SharedSecretLength)))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedSecret));
		}
	}

	// Called after the ML-KEM parts, which throw before writing if drawing m fails, so that a failure leaves both buffers unchanged. Q was checked to be on the curve when it was imported, and the ephemeral key lies in [1, n − 1].
	private readonly void WriteECParts(in FieldElement<TOrder> ephemeral, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ECGroup<TCurve, TField, TOrder>.MultiplyEncodeExportX(in _ecKey.PublicPoint, in ephemeral, ciphertext.Slice(0, ECPublicKeyLength), sharedSecret.Slice(0, ECSharedSecretLength));
	}
}
