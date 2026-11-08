using CryptoBase.EllipticCurves;

namespace CryptoBase.KeyAgreements.Ecdh;

/// <summary>
/// Provides elliptic curve Diffie–Hellman (ECDH) over the SM2 curve, curveSM2 of RFC 8998.
/// </summary>
/// <remarks>
/// <para>
/// The private key is big-endian and must lie in [1, n − 1]. The public key is in the uncompressed encoding, and <see cref="TryDeriveSharedSecret" /> returns <see langword="false" /> unless the peer public key is in that encoding, has both coordinates below the field prime and lies on the curve.
/// </para>
/// <para>
/// The shared secret is the x-coordinate of the shared point as big-endian bytes, as ECDHE over curveSM2 in TLS 1.3 (RFC 8998) takes it. This is not the key exchange protocol of GB/T 32918.3, which <see cref="SM2.SM2KeyExchange" /> provides. Exports and derivations may run concurrently on one instance.
/// </para>
/// </remarks>
public sealed class EcdhSM2 : IKeyAgreement<EcdhSM2>
{
	private EcdhKey<SM2Curve, SM2CurveField, SM2Order> _key;
	private bool _disposed;

	private EcdhSM2() { }

	/// <inheritdoc />
	public static int PrivateKeyLength => EcdhKey<SM2Curve, SM2CurveField, SM2Order>.PrivateKeyLength;

	/// <inheritdoc />
	public static int PublicKeyLength => EcdhKey<SM2Curve, SM2CurveField, SM2Order>.PublicKeyLength;

	/// <inheritdoc />
	public static int SharedSecretLength => EcdhKey<SM2Curve, SM2CurveField, SM2Order>.SharedSecretLength;

	/// <inheritdoc />
	public static EcdhSM2 GenerateKey()
	{
		EcdhSM2 ecdh = new();
		ecdh._key.GenerateKey();
		return ecdh;
	}

	/// <inheritdoc />
	public static EcdhSM2 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		EcdhSM2 ecdh = new();
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
