namespace CryptoBase.KeyAgreements.Xdh;

/// <summary>
/// Provides the X25519 Diffie–Hellman function over Curve25519 (RFC 7748).
/// </summary>
/// <remarks>
/// <para>
/// Every 32-byte value is a valid private key. It is clamped when used, and <see cref="ExportPrivateKey" /> writes back the bytes that were imported. The public key and the shared secret are 32-byte little-endian u-coordinates.
/// </para>
/// <para>
/// A peer public key of 32 bytes is accepted in any encoding: the most significant bit is ignored and a u-coordinate of the field prime or more is reduced, as RFC 7748 requires. <see cref="TryDeriveSharedSecret" /> returns <see langword="false" /> if the peer public key has the wrong length or a point of small order, which gives an all-zero shared secret. Exports and derivations may run concurrently on one instance.
/// </para>
/// </remarks>
public sealed class X25519 : IKeyAgreement<X25519>
{
	private X25519Key _key;
	private bool _disposed;

	private X25519() { }

	/// <inheritdoc />
	public static int PrivateKeyLength => X25519Key.PrivateKeyLength;

	/// <inheritdoc />
	public static int PublicKeyLength => X25519Key.PublicKeyLength;

	/// <inheritdoc />
	public static int SharedSecretLength => X25519Key.SharedSecretLength;

	/// <inheritdoc />
	public static X25519 GenerateKey()
	{
		X25519 x25519 = new();
		x25519._key.GenerateKey();
		return x25519;
	}

	/// <inheritdoc />
	public static X25519 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		X25519 x25519 = new();
		x25519._key.ImportPrivateKey(source);
		return x25519;
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
