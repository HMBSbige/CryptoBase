using CryptoBase.EllipticCurves;

namespace CryptoBase.KeyAgreements.Ecdh;

// As with ECKey, keep a key in one writable location and do not copy it.
internal struct EcdhKey<TCurve, TField, TOrder> : IDiffieHellmanKey<EcdhKey<TCurve, TField, TOrder>>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private ECKey<TCurve, TField, TOrder> _key;

	public static int PrivateKeyLength => ECKey<TCurve, TField, TOrder>.PrivateKeyLength;

	public static int PublicKeyLength => ECKey<TCurve, TField, TOrder>.PublicKeyLength;

	public static int SharedSecretLength => ECKey<TCurve, TField, TOrder>.SharedSecretLength;

	public static bool ClampsPrivateKey => false;

	// Clears the bits above the bit length of n, as GeneratePrivateScalar does.
	public static byte PrivateKeyMask => (byte)(0xFF >> 8 * TOrder.ByteLength - TOrder.BitLength);

	public readonly bool HasPrivateKey => _key.HasPrivateKey;

	public readonly bool HasPublicKey => _key.HasPublicKey;

	internal void GenerateKey()
	{
		_key.GenerateKey();
	}

	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		if (!_key.TryImportPrivateKey(source))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}
	}

	public bool TryImportPrivateKey(ReadOnlySpan<byte> source)
	{
		return _key.TryImportPrivateKey(source);
	}

	// The cofactor is 1 and a private key lies in [1, n − 1], so its product with any point on the curve is not the point at infinity.
	public bool TryImportPublicKey(ReadOnlySpan<byte> source)
	{
		return _key.TryImportPublicKey(source);
	}

	public readonly int ExportPrivateKey(Span<byte> destination)
	{
		return _key.ExportPrivateKey(destination);
	}

	public readonly int ExportPublicKey(Span<byte> destination)
	{
		return _key.ExportPublicKey(destination);
	}

	public readonly bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		// ECKey checks the length too, but under the name destination.
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));
		return _key.TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	public static void DeriveSharedSecret(in EcdhKey<TCurve, TField, TOrder> privateKey, in EcdhKey<TCurve, TField, TOrder> publicKey, Span<byte> destination)
	{
		bool derived = ECGroup<TCurve, TField, TOrder>.TryMultiplyExportX(in publicKey._key.PublicPoint, in privateKey._key.PrivateScalar, destination.Slice(0, SharedSecretLength));
		Debug.Assert(derived);
	}

	// GeneratePrivateScalar draws before anything is written.
	public static void GenerateEphemeral(in EcdhKey<TCurve, TField, TOrder> publicKey, Span<byte> ephemeralPublicKey, Span<byte> sharedSecret)
	{
		FieldElement<TOrder> ephemeral = default;

		try
		{
			ECKey<TCurve, TField, TOrder>.GeneratePrivateScalar(SystemRandom.Fill, out ephemeral);
			ECGroup<TCurve, TField, TOrder>.MultiplyEncodeExportX(in publicKey._key.PublicPoint, in ephemeral, ephemeralPublicKey.Slice(0, PublicKeyLength), sharedSecret.Slice(0, SharedSecretLength));
		}
		finally
		{
			ephemeral.ZeroMemory();
		}
	}

	public void Clear()
	{
		_key.Clear();
	}
}
