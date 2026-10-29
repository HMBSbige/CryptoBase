using CryptoBase.EllipticCurves;

namespace CryptoBase.KeyAgreements.Ecdh;

// As with ECKey, keep a key in one writable location and do not copy it.
internal struct EcdhKey<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private ECKey<TCurve, TField, TOrder> _key;

	internal static int PrivateKeyLength => ECKey<TCurve, TField, TOrder>.PrivateKeyLength;

	internal static int PublicKeyLength => ECKey<TCurve, TField, TOrder>.PublicKeyLength;

	internal static int SharedSecretLength => ECKey<TCurve, TField, TOrder>.SharedSecretLength;

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

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		return _key.ExportPrivateKey(destination);
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		return _key.ExportPublicKey(destination);
	}

	internal readonly bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		// ECKey checks the length too, but under the name destination.
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));
		return _key.TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	internal void Clear()
	{
		_key.Clear();
	}
}
