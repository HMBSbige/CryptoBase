using CryptoBase.Kems.MLKem;
using CryptoBase.KeyAgreements.Xdh;

namespace CryptoBase.Kems.Hybrid;

// The ML-KEM part goes first in every encoding and in the shared secret, unlike in ECMLKemKey. As with X25519Key and MLKemKey, keep a key in one writable location and do not copy it.
internal struct X25519MLKemKey<TParameters> where TParameters : struct, IMLKemParameters
{
	private MLKemKey<TParameters> _mlKemKey;
	private X25519Key _x25519Key;

	internal static int EncapsulationKeyLength => MLKemKey<TParameters>.EncapsulationKeyLength + X25519Key.PublicKeyLength;

	internal static int DecapsulationKeyLength => MLKemKey<TParameters>.DecapsulationKeyLength + X25519Key.PrivateKeyLength;

	internal static int PrivateSeedLength => MLKemKey<TParameters>.PrivateSeedLength + X25519Key.PrivateKeyLength;

	internal static int CiphertextLength => MLKemCiphertextLength + X25519Key.PublicKeyLength;

	internal static int SharedSecretLength => MLKemKey<TParameters>.SharedSecretLength + X25519Key.SharedSecretLength;

	// The X25519 private key is held whenever the ML-KEM decapsulation key is.
	internal readonly bool HasPrivateSeed => _mlKemKey.HasPrivateSeed;

	internal readonly bool HasDecapsulationKey => _mlKemKey.HasDecapsulationKey;

	private static int MLKemCiphertextLength => MLKemKey<TParameters>.CiphertextLength;

	// Here and in the two private imports, the ML-KEM part goes first: MLKemKey throws without keeping any of the new key, and every 32 bytes are an X25519 private key, so only a failure to draw them needs the ML-KEM part cleared.
	internal void GenerateKey()
	{
		_mlKemKey.GenerateKey();

		try
		{
			_x25519Key.GenerateKey();
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

		int mlKemLength = MLKemKey<TParameters>.PrivateSeedLength;
		_mlKemKey.ImportPrivateSeed(source.Slice(0, mlKemLength));
		_x25519Key.ImportPrivateKey(source.Slice(mlKemLength));
	}

	internal void ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, DecapsulationKeyLength, nameof(source));

		int mlKemLength = MLKemKey<TParameters>.DecapsulationKeyLength;
		_mlKemKey.ImportDecapsulationKey(source.Slice(0, mlKemLength));
		_x25519Key.ImportPrivateKey(source.Slice(mlKemLength));
	}

	// A small-order X25519 key would give the all-zero secret, which TryDecapsulate rejects, whatever the ephemeral key: it is rejected here, so that Encapsulate cannot fail.
	internal void ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, EncapsulationKeyLength, nameof(source));

		int mlKemLength = MLKemKey<TParameters>.EncapsulationKeyLength;

		if (!_x25519Key.TryImportPublicKey(source.Slice(mlKemLength)))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		_mlKemKey.ImportEncapsulationKey(source.Slice(0, mlKemLength));
	}

	internal readonly int ExportPrivateSeed(Span<byte> destination)
	{
		if (!HasPrivateSeed)
		{
			ThrowHelper.ThrowMissingKey("private seed");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateSeedLength, nameof(destination));

		int mlKemLength = _mlKemKey.ExportPrivateSeed(destination);
		_x25519Key.ExportPrivateKey(destination.Slice(mlKemLength));
		return PrivateSeedLength;
	}

	internal int ExportDecapsulationKey(Span<byte> destination)
	{
		if (!HasDecapsulationKey)
		{
			ThrowHelper.ThrowMissingKey("decapsulation key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, DecapsulationKeyLength, nameof(destination));

		int mlKemLength = _mlKemKey.ExportDecapsulationKey(destination);
		_x25519Key.ExportPrivateKey(destination.Slice(mlKemLength));
		return DecapsulationKeyLength;
	}

	internal readonly int ExportEncapsulationKey(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, EncapsulationKeyLength, nameof(destination));

		int mlKemLength = _mlKemKey.ExportEncapsulationKey(destination);
		_x25519Key.ExportPublicKey(destination.Slice(mlKemLength));
		return EncapsulationKeyLength;
	}

	[SkipLocalsInit]
	internal void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		using CryptoBuffer<byte> ephemeral = new(stackalloc byte[X25519Key.PrivateKeyLength]);
		SystemRandom.Fill(ephemeral.Span);
		_mlKemKey.Encapsulate(ciphertext.Slice(0, MLKemCiphertextLength), sharedSecret.Slice(0, MLKemKey<TParameters>.SharedSecretLength));
		WriteX25519Parts(ephemeral.Span, ciphertext, sharedSecret);
	}

	[SkipLocalsInit]
	internal void Encapsulate(ReadOnlySpan<byte> ephemeralPrivateKey, ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(ephemeralPrivateKey.Length, X25519Key.PrivateKeyLength, nameof(ephemeralPrivateKey));
		ThrowIfCannotEncapsulate(ciphertext, sharedSecret);

		using CryptoBuffer<byte> ephemeral = new(stackalloc byte[X25519Key.PrivateKeyLength]);
		ephemeralPrivateKey.CopyTo(ephemeral.Span);
		_mlKemKey.Encapsulate(message, ciphertext.Slice(0, MLKemCiphertextLength), sharedSecret.Slice(0, MLKemKey<TParameters>.SharedSecretLength));
		WriteX25519Parts(ephemeral.Span, ciphertext, sharedSecret);
	}

	// Both parts are computed before sharedSecret is written, since ciphertext may overlap it. The X25519 part fails just for an ephemeral key of small order, which the ciphertext alone decides.
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

		int mlKemLength = MLKemKey<TParameters>.SharedSecretLength;
		using CryptoBuffer<byte> secret = new(stackalloc byte[SharedSecretLength]);

		if (!_x25519Key.TryDeriveSharedSecret(ciphertext.Slice(MLKemCiphertextLength), secret.Span.Slice(mlKemLength)))
		{
			return false;
		}

		bool decapsulated = _mlKemKey.TryDecapsulate(ciphertext.Slice(0, MLKemCiphertextLength), secret.Span.Slice(0, mlKemLength));
		Debug.Assert(decapsulated);

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	internal void Clear()
	{
		_mlKemKey.Clear();
		_x25519Key.Clear();
	}

	// The ML-KEM part checks for its own key; the X25519 key is read directly, so it is checked here.
	private readonly void ThrowIfCannotEncapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		if (!_x25519Key.HasPublicKey)
		{
			ThrowHelper.ThrowMissingKey("encapsulation key");
		}

		KemOutputs.ThrowIfInvalid(ciphertext, CiphertextLength, sharedSecret, SharedSecretLength);
	}

	// Called after the ML-KEM parts, which throw before writing if drawing m fails, so that a failure leaves both buffers unchanged. The public key is not of small order, so the shared secret is not all zeros and the derivation cannot fail.
	private readonly void WriteX25519Parts(ReadOnlySpan<byte> ephemeral, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		X25519Key.DerivePublicKeyAndSharedSecret(ephemeral, _x25519Key.PublicKey, ciphertext.Slice(MLKemCiphertextLength, X25519Key.PublicKeyLength), sharedSecret.Slice(MLKemKey<TParameters>.SharedSecretLength, X25519Key.SharedSecretLength));
	}
}
