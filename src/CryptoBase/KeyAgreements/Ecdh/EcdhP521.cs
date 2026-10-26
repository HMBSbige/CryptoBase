using CryptoBase.EllipticCurves;

namespace CryptoBase.KeyAgreements.Ecdh;

/// <summary>
/// Provides elliptic curve Diffie–Hellman (ECDH) over the P-521 curve.
/// </summary>
/// <remarks>
/// <para>
/// The private key is big-endian and must lie in [1, n − 1]. The public key is in the uncompressed encoding, and <see cref="TryDeriveSharedSecret" /> returns <see langword="false" /> unless the peer public key is in that encoding, has both coordinates below the field prime and lies on the curve.
/// </para>
/// <para>
/// The shared secret is the x-coordinate of the shared point as big-endian bytes. Exports and derivations may run concurrently on one instance.
/// </para>
/// </remarks>
public sealed class EcdhP521 : IKeyAgreement<EcdhP521>
{
	private EcdhKey<P521Curve, P521CurveField, P521Order> _key;
	private bool _disposed;

	private EcdhP521() { }

	/// <inheritdoc />
	public static int PrivateKeyLength => EcdhKey<P521Curve, P521CurveField, P521Order>.PrivateKeyLength;

	/// <inheritdoc />
	public static int PublicKeyLength => EcdhKey<P521Curve, P521CurveField, P521Order>.PublicKeyLength;

	/// <inheritdoc />
	public static int SharedSecretLength => EcdhKey<P521Curve, P521CurveField, P521Order>.SharedSecretLength;

	/// <inheritdoc />
	public static EcdhP521 GenerateKey()
	{
		EcdhP521 ecdh = new();
		ecdh._key.GenerateKey();
		return ecdh;
	}

	/// <inheritdoc />
	public static EcdhP521 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		EcdhP521 ecdh = new();
		ecdh._key.ImportPrivateKey(source);
		return ecdh;
	}

	/// <inheritdoc />
	public int ExportPrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPrivateKey(destination);
	}

	/// <inheritdoc />
	public int ExportPublicKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPublicKey(destination);
	}

	/// <inheritdoc />
	public bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_key.Clear();
		_disposed = true;
	}
}
