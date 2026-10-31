using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Ecdsa;

/// <summary>
/// Provides ECDSA over the curve P-256.
/// </summary>
/// <remarks>
/// <para>
/// The nonce is derived from the private key, the hash and fresh system randomness, so signing a message twice gives two different signatures.
/// s is not reduced to the lower half of [1, n − 1]. Signatures are in DER, and verification rejects any other encoding of r and s. Signing and verification may run concurrently on one instance.
/// </para>
/// <para>
/// The second verification with an instance builds a table from the public key, which makes that verification slower and every later one faster. The instance keeps the table, about 10 KB, until it is disposed, so to verify many signatures with one key, keep one instance rather than import the key for each.
/// </para>
/// <para>
/// SubjectPublicKeyInfo and PKCS #8 name the curve by its OID and hold the public key uncompressed; other parameters and point encodings are rejected. A PKCS #8 export holds the private key, the curve and the public key. A PKCS #8 import accepts a key without the curve or the public key, but rejects either, in the inner or the outer structure, if it does not match the private key.
/// </para>
/// </remarks>
public sealed class EcdsaP256 : IEcdsa<EcdsaP256>
{
	private EcdsaKey<P256Curve, P256CurveField, P256Order> _key;
	private bool _disposed;

	private EcdsaP256() { }

	/// <summary>
	/// Gets the length of the private key, in bytes.
	/// </summary>
	public static int PrivateKeyLength => EcdsaKey<P256Curve, P256CurveField, P256Order>.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PublicKeyLength => EcdsaKey<P256Curve, P256CurveField, P256Order>.PublicKeyLength;

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
			return EcdsaKey<P256Curve, P256CurveField, P256Order>.GetSubjectPublicKeyInfoLength(AlgorithmIdentifier);
		}
	}

	/// <inheritdoc />
	public int Pkcs8PrivateKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.GetPkcs8PrivateKeyLength(AlgorithmIdentifier);
		}
	}

	internal static ReadOnlySpan<byte> AlgorithmIdentifier =>
	[
		0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
	];

	/// <summary>
	/// Generates a key pair from a new random private key.
	/// </summary>
	/// <returns>An instance that holds the private key and the public key.</returns>
	public static EcdsaP256 GenerateKey()
	{
		EcdsaP256 key = new();
		key._key.GenerateKey();
		return key;
	}

	/// <summary>
	/// Imports a private key.
	/// </summary>
	/// <remarks>Implementation-owned key material is erased if the key is invalid.</remarks>
	/// <param name="source">The private key as big-endian bytes, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not in [1, n − 1].</exception>
	public static EcdsaP256 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		EcdsaP256 key = new();
		key._key.ImportPrivateKey(source);
		return key;
	}

	/// <summary>
	/// Imports a public key.
	/// </summary>
	/// <param name="source">The public key in the uncompressed encoding, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a point on the curve.</exception>
	public static EcdsaP256 ImportPublicKey(ReadOnlySpan<byte> source)
	{
		EcdsaP256 key = new();
		key._key.ImportPublicKey(source);
		return key;
	}

	/// <inheritdoc />
	public static EcdsaP256 ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		EcdsaP256 key = new();
		key._key.ImportSubjectPublicKeyInfo(AlgorithmIdentifier, source);
		return key;
	}

	/// <inheritdoc />
	public static EcdsaP256 ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		EcdsaP256 key = new();
		key._key.ImportPkcs8PrivateKey(AlgorithmIdentifier, source);
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
		return _key.ExportSubjectPublicKeyInfo(AlgorithmIdentifier, destination);
	}

	/// <inheritdoc />
	public int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPkcs8PrivateKey(AlgorithmIdentifier, destination);
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return EcdsaKey<P256Curve, P256CurveField, P256Order>.Supports(algorithm);
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return EcdsaKey<P256Curve, P256CurveField, P256Order>.GetMaxSignatureLength(algorithm);
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

	int IEcdsa<EcdsaP256>.Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Sign(algorithm, message, additionalData, destination);
	}

	int IEcdsa<EcdsaP256>.SignHash(SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.SignHash(algorithm, hash, additionalData, destination);
	}

	bool IEcdsa<EcdsaP256>.VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.VerifyHash(hash, signature);
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
