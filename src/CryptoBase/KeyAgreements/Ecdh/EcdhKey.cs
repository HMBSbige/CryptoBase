using CryptoBase.EllipticCurves;

namespace CryptoBase.KeyAgreements.Ecdh;

// As with EcKey, keep a key in one writable location and do not copy it.
internal struct EcdhKey<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	private EcKey<TCurve, TField, TOrder> _key;

	internal static int PrivateKeyLength => EcKey<TCurve, TField, TOrder>.PrivateKeyLength;

	internal static int PublicKeyLength => EcKey<TCurve, TField, TOrder>.PublicKeyLength;

	internal static int SharedSecretLength => EcKey<TCurve, TField, TOrder>.SharedSecretLength;

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
		// EcKey checks the length too, but under the name destination.
		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));
		return _key.TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	internal void Clear()
	{
		_key.Clear();
	}
}
