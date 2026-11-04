namespace CryptoBase.Signatures.EdDsa;

/// <summary>
/// Provides Ed448 and Ed448ph, the Edwards-curve digital signature algorithm over edwards448 (RFC 8032).
/// </summary>
/// <remarks>
/// <para>
/// The private key is the 57-byte secret of RFC 8032; every 57-byte value is a valid private key. The public key is a point encoded in 57 bytes, and a signature is R ‖ S in 114 bytes.
/// Signing is deterministic: signing a message twice with one key gives the same signature. Signing and verification may run concurrently on one instance.
/// </para>
/// <para>
/// Ed448 and Ed448ph take any context of up to <see cref="MaxContextLength" /> bytes, the empty one included.
/// <see cref="SignatureAlgorithm.Ed448" /> is Ed448 with an empty context.
/// </para>
/// <para>
/// Verification checks the cofactorless equation [S]B = R + [k]A of RFC 8032, Sec. 5.2.7 with k reduced modulo the group order: it rejects a signature whose S is not below the group order, and compares R byte for byte with the encoding of [S]B − [k]A, so that no other encoding of R verifies. For a public key with a component of small order, the result may differ from that of the unreduced equation; every signature that verifies satisfies the cofactored equation of RFC 8032.
/// A public key must be the canonical encoding of a point. Points of small order are accepted, as the public key and as R.
/// </para>
/// <para>
/// From its second verification on, an instance keeps a table of about 25 KB built from the public key, which the later verifications use, until it is disposed. To verify many signatures with one key, keep one instance rather than import the key for each.
/// </para>
/// <para>
/// The DER encodings are those of RFC 8410, with the parameters of the algorithm identifier absent. A PKCS #8 export holds the private key alone in a version 1 PrivateKeyInfo. A PKCS #8 import accepts version 1 and version 2, skips attributes, and rejects a public key that does not match the private key.
/// </para>
/// </remarks>
public sealed class Ed448 : ISignatureKey<Ed448>
{
	private Ed448Key _key;
	private bool _disposed;

	private Ed448() { }

	/// <summary>
	/// Gets the length of the private key, in bytes.
	/// </summary>
	public static int PrivateKeyLength => Ed448Key.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the public key, in bytes.
	/// </summary>
	public static int PublicKeyLength => Ed448Key.PublicKeyLength;

	/// <summary>
	/// Gets the length of a signature, in bytes.
	/// </summary>
	public static int SignatureLength => Ed448Key.SignatureLength;

	/// <summary>
	/// Gets the maximum length of a context string, in bytes.
	/// </summary>
	public static int MaxContextLength => Ed448Key.MaxContextLength;

	/// <inheritdoc />
	public bool HasPrivateKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.HasPrivateKey;
		}
	}

	/// <inheritdoc />
	public int SubjectPublicKeyInfoLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return Ed448Key.SubjectPublicKeyInfoLength;
		}
	}

	/// <inheritdoc />
	public int Pkcs8PrivateKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.Pkcs8PrivateKeyLength;
		}
	}

	/// <summary>
	/// Generates a key pair from a new random private key.
	/// </summary>
	/// <returns>An instance that holds the private key and the public key.</returns>
	public static Ed448 GenerateKey()
	{
		Ed448 key = new();
		key._key.GenerateKey();
		return key;
	}

	/// <summary>
	/// Imports a private key and derives its public key.
	/// </summary>
	/// <param name="source">The private key, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length.</exception>
	public static Ed448 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		Ed448 key = new();
		key._key.ImportPrivateKey(source);
		return key;
	}

	/// <summary>
	/// Imports a public key.
	/// </summary>
	/// <param name="source">The public key, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not the canonical encoding of a point.</exception>
	public static Ed448 ImportPublicKey(ReadOnlySpan<byte> source)
	{
		Ed448 key = new();
		key._key.ImportPublicKey(source);
		return key;
	}

	/// <inheritdoc />
	public static Ed448 ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		Ed448 key = new();
		key._key.ImportSubjectPublicKeyInfo(source);
		return key;
	}

	/// <inheritdoc />
	public static Ed448 ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		Ed448 key = new();
		key._key.ImportPkcs8PrivateKey(source);
		return key;
	}

	/// <summary>
	/// Writes the private key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPrivateKey(destination);
	}

	/// <summary>
	/// Writes the public key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PublicKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPublicKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPublicKey(destination);
	}

	/// <inheritdoc />
	public int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportSubjectPublicKeyInfo(destination);
	}

	/// <inheritdoc />
	public int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPkcs8PrivateKey(destination);
	}

	/// <summary>
	/// Signs <paramref name="message" /> with Ed448 (RFC 8032, Sec. 5.2.6).
	/// </summary>
	/// <remarks>
	/// <paramref name="message" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.
	/// </remarks>
	/// <param name="message">The message.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="SignatureLength" /> bytes long.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns>The value of <see cref="SignatureLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short, or <paramref name="context" /> is too long.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Sign(ReadOnlySpan<byte> message, Span<byte> destination, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Sign(message, context, destination);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of <paramref name="message" /> with Ed448 (RFC 8032, Sec. 5.2.7).
	/// </summary>
	/// <param name="message">The message.</param>
	/// <param name="signature">The signature.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="context" /> is too long.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Verify(message, signature, context);
	}

	/// <summary>
	/// Signs the SHAKE256 hash of a message with Ed448ph (RFC 8032, Sec. 5.2.6).
	/// </summary>
	/// <remarks>
	/// <paramref name="hash" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.
	/// </remarks>
	/// <param name="hash">The SHAKE256 hash of the message (PH of RFC 8032, Sec. 5.2), exactly 64 bytes long.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="SignatureLength" /> bytes long.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns>The value of <see cref="SignatureLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="hash" /> has the wrong length, <paramref name="destination" /> is too short, or <paramref name="context" /> is too long.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int SignPreHash(ReadOnlySpan<byte> hash, Span<byte> destination, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.SignPreHash(hash, context, destination);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of the SHAKE256 hash of a message with Ed448ph (RFC 8032, Sec. 5.2.7).
	/// </summary>
	/// <param name="hash">The SHAKE256 hash of the message (PH of RFC 8032, Sec. 5.2), exactly 64 bytes long.</param>
	/// <param name="signature">The signature.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="hash" /> has the wrong length, or <paramref name="context" /> is too long.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.VerifyPreHash(hash, signature, context);
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return Ed448Key.Supports(algorithm);
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return Ed448Key.GetMaxSignatureLength(algorithm);
	}

	/// <inheritdoc />
	public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Sign(algorithm, message, destination);
	}

	/// <inheritdoc />
	public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Verify(algorithm, message, signature);
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
