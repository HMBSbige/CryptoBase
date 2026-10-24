using CryptoBase.EllipticCurves;
using CryptoBase.Kems.MLKem;

namespace CryptoBase.Kems.Hybrid;

// As with EcKey and MLKemKey, keep a key in one writable location and do not copy it.
internal struct EcMLKemKey<TCurve, TField, TOrder, TParameters>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
	where TParameters : struct, IMLKemParameters
{
	private EcKey<TCurve, TField, TOrder> _ecKey;
	private MLKemKey<TParameters> _mlKemKey;

	internal static int EncapsulationKeyLength => EcPublicKeyLength + MLKemKey<TParameters>.EncapsulationKeyLength;

	internal static int DecapsulationKeyLength => EcPrivateKeyLength + MLKemKey<TParameters>.DecapsulationKeyLength;

	internal static int PrivateSeedLength => EcPrivateKeyLength + MLKemKey<TParameters>.PrivateSeedLength;

	internal static int CiphertextLength => EcPublicKeyLength + MLKemKey<TParameters>.CiphertextLength;

	internal static int SharedSecretLength => EcSharedSecretLength + MLKemKey<TParameters>.SharedSecretLength;

	// The elliptic curve private key is held whenever the ML-KEM decapsulation key is.
	internal readonly bool HasPrivateSeed => _mlKemKey.HasPrivateSeed;

	internal readonly bool HasDecapsulationKey => _mlKemKey.HasDecapsulationKey;

	private static int EcPrivateKeyLength => EcKey<TCurve, TField, TOrder>.PrivateKeyLength;

	private static int EcPublicKeyLength => EcKey<TCurve, TField, TOrder>.PublicKeyLength;

	private static int EcSharedSecretLength => EcKey<TCurve, TField, TOrder>.SharedSecretLength;

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

		_mlKemKey.ImportPrivateSeed(source.Slice(EcPrivateKeyLength));

		if (!_ecKey.TryImportPrivateKey(source.Slice(0, EcPrivateKeyLength)))
		{
			_mlKemKey.Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, DecapsulationKeyLength, nameof(source));

		_mlKemKey.ImportDecapsulationKey(source.Slice(EcPrivateKeyLength));

		if (!_ecKey.TryImportPrivateKey(source.Slice(0, EcPrivateKeyLength)))
		{
			_mlKemKey.Clear();
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	internal void ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, EncapsulationKeyLength, nameof(source));

		if (!_ecKey.TryImportPublicKey(source.Slice(0, EcPublicKeyLength)))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		_mlKemKey.ImportEncapsulationKey(source.Slice(EcPublicKeyLength));
	}

	internal readonly int ExportPrivateSeed(Span<byte> destination)
	{
		if (!HasPrivateSeed)
		{
			ThrowHelper.ThrowMissingKey("private seed");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateSeedLength, nameof(destination));

		_ecKey.ExportPrivateKey(destination);
		_mlKemKey.ExportPrivateSeed(destination.Slice(EcPrivateKeyLength));
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
		_mlKemKey.ExportDecapsulationKey(destination.Slice(EcPrivateKeyLength));
		return DecapsulationKeyLength;
	}

	internal readonly int ExportEncapsulationKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EncapsulationKeyLength, nameof(destination));

		_ecKey.ExportPublicKey(destination);
		_mlKemKey.ExportEncapsulationKey(destination.Slice(EcPublicKeyLength));
		return EncapsulationKeyLength;
	}

	internal void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfInvalidEncapsulationBuffers(ciphertext, sharedSecret);

		EcKey<TCurve, TField, TOrder> ephemeral = default;

		try
		{
			ephemeral.GenerateKey();
			_mlKemKey.Encapsulate(ciphertext.Slice(EcPublicKeyLength), sharedSecret.Slice(EcSharedSecretLength));
			WriteEcParts(in ephemeral, ciphertext, sharedSecret);
		}
		finally
		{
			ephemeral.Clear();
		}
	}

	internal void Encapsulate(ReadOnlySpan<byte> ephemeralPrivateKey, ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfInvalidEncapsulationBuffers(ciphertext, sharedSecret);

		EcKey<TCurve, TField, TOrder> ephemeral = default;

		try
		{
			if (!ephemeral.TryImportPrivateKey(ephemeralPrivateKey))
			{
				ThrowHelper.ThrowInvalidKey(nameof(ephemeralPrivateKey));
			}

			_mlKemKey.Encapsulate(message, ciphertext.Slice(EcPublicKeyLength), sharedSecret.Slice(EcSharedSecretLength));
			WriteEcParts(in ephemeral, ciphertext, sharedSecret);
		}
		finally
		{
			ephemeral.Clear();
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
		if (!_ecKey.TryDeriveSharedSecret(ciphertext.Slice(0, EcPublicKeyLength), secret.Span))
		{
			return false;
		}

		bool decapsulated = _mlKemKey.TryDecapsulate(ciphertext.Slice(EcPublicKeyLength), secret.Span.Slice(EcSharedSecretLength));
		Debug.Assert(decapsulated);

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	internal void Clear()
	{
		_ecKey.Clear();
		_mlKemKey.Clear();
	}

	private static void ThrowIfInvalidEncapsulationBuffers(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(ciphertext.Length, CiphertextLength, nameof(ciphertext));
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		if (ciphertext.Slice(0, CiphertextLength).Overlaps(sharedSecret.Slice(0, SharedSecretLength)))
		{
			ThrowHelper.ThrowOutputsOverlap(nameof(sharedSecret));
		}
	}

	// Called after the ML-KEM parts, which throw before writing if drawing m fails, so that a failure leaves both buffers unchanged. The derivation cannot fail, since Q is a point on the curve.
	[SkipLocalsInit]
	private readonly void WriteEcParts(in EcKey<TCurve, TField, TOrder> ephemeral, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		Span<byte> publicKey = stackalloc byte[EcPublicKeyLength];
		_ecKey.ExportPublicKey(publicKey);
		bool derived = ephemeral.TryDeriveSharedSecret(publicKey, sharedSecret);
		Debug.Assert(derived);

		ephemeral.ExportPublicKey(ciphertext);
	}
}
