namespace CryptoBase.KeyAgreements.Xdh;

/// <summary>
/// Provides the X448 Diffie–Hellman function over Curve448 (RFC 7748).
/// </summary>
/// <remarks>
/// <para>
/// Every 56-byte value is a valid private key. It is clamped when used, and <see cref="ExportPrivateKey" /> writes back the bytes that were imported. The public key and the shared secret are 56-byte little-endian u-coordinates.
/// </para>
/// <para>
/// A peer public key of 56 bytes is accepted in any encoding: all its bits count, and a u-coordinate of the field prime or more is reduced, as RFC 7748 requires. <see cref="TryDeriveSharedSecret" /> returns <see langword="false" /> if the peer public key has the wrong length or the shared secret is all zeros, as it is for a point of small order, or for every point of the curve if the private key clamps to 4L, a multiple of the order. Exports and derivations may run concurrently on one instance.
/// </para>
/// </remarks>
public sealed class X448 : IKeyAgreement<X448>
{
	private X448Key _key;
	private bool _disposed;

	private X448() { }

	/// <inheritdoc />
	public static int PrivateKeyLength => X448Key.PrivateKeyLength;

	/// <inheritdoc />
	public static int PublicKeyLength => X448Key.PublicKeyLength;

	/// <inheritdoc />
	public static int SharedSecretLength => X448Key.SharedSecretLength;

	/// <inheritdoc />
	public static X448 GenerateKey()
	{
		X448 x448 = new();
		x448._key.GenerateKey();
		return x448;
	}

	/// <inheritdoc />
	public static X448 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		X448 x448 = new();
		x448._key.ImportPrivateKey(source);
		return x448;
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
	/// <remarks>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="peerPublicKey" /> does not have exactly <see cref="PublicKeyLength" /> bytes or the shared secret is all zeros. The secret is all zeros for a peer point of small order, whatever the private key, and for every point of the curve if the private key is one of the eight values that clamp to 4L, a multiple of the order of the curve. The result thus depends on the private key only in that case, which its all-zero public key reveals.
	/// </para>
	/// <para>
	/// The shared secret is not uniformly random: derive keys from it with a key derivation function. It need not bind the public keys, so a protocol that relies on that binding must include both public keys in its key derivation or transcript.
	/// </para>
	/// <para>
	/// The exceptions take precedence: they are thrown even if <paramref name="peerPublicKey" /> is also unusable. <paramref name="peerPublicKey" /> may overlap <paramref name="sharedSecret" />. If the method returns <see langword="false" /> or throws, <paramref name="sharedSecret" /> remains unchanged.
	/// </para>
	/// </remarks>
	/// <returns><see langword="false" /> if <paramref name="peerPublicKey" /> has the wrong length or the shared secret is all zeros; otherwise, <see langword="true" />.</returns>
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
