namespace CryptoBase.Signatures.MLDsa;

/// <summary>
/// Provides ML-DSA-65, the module-lattice-based digital signature algorithm of FIPS 204 with the parameter set for security category 3.
/// </summary>
/// <remarks>
/// <para>
/// Importing a private key checks that s1 and s2 lie in [−η, η] and that t0 and tr follow from ρ, s1 and s2. Every byte
/// string of <see cref="PublicKeyLength" /> bytes is a public key, so importing one checks only its length. Signing and
/// verification may run concurrently on one instance.
/// </para>
/// <para>
/// Signing is hedged with 32 bytes of system randomness, so signing a message twice gives two different signatures.
/// The DER encodings are those of RFC 9881: a PKCS #8 export holds the seed form if the instance holds the seed, and the expandedKey form
/// otherwise, and a PKCS #8 import accepts the seed, expandedKey and both forms, keeps the seed if there is one, and rejects a seed that does
/// not expand to the expandedKey beside it, or a publicKey that does not match the private key.
/// <see cref="SignatureAlgorithm.MLDsa65" /> is ML-DSA-65 with an empty context.
/// </para>
/// </remarks>
public sealed class MLDsa65 : IMLDsa<MLDsa65>
{
	private MLDsaKey<MLDsa65Parameters> _key;
	private bool _disposed;

	private MLDsa65() { }

	/// <summary>
	/// Gets the length of the private seed ξ from which the key pair derives, in bytes.
	/// </summary>
	public static int PrivateSeedLength => MLDsaKey<MLDsa65Parameters>.PrivateSeedLength;

	/// <summary>
	/// Gets the length of the private key in the encoding of FIPS 204, Algorithm 24, in bytes.
	/// </summary>
	public static int PrivateKeyLength => MLDsaKey<MLDsa65Parameters>.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the public key in the encoding of FIPS 204, Algorithm 22, in bytes.
	/// </summary>
	public static int PublicKeyLength => MLDsaKey<MLDsa65Parameters>.PublicKeyLength;

	/// <summary>
	/// Gets the length of a signature, in bytes.
	/// </summary>
	public static int SignatureLength => MLDsaKey<MLDsa65Parameters>.SignatureLength;

	/// <summary>
	/// Gets the length of the message representative μ, in bytes.
	/// </summary>
	public static int MuLength => MLDsaKey<MLDsa65Parameters>.MuLength;

	/// <summary>
	/// Gets the maximum length of a context string, in bytes.
	/// </summary>
	public static int MaxContextLength => MLDsaKey<MLDsa65Parameters>.MaxContextLength;

	/// <summary>
	/// Gets a value that indicates whether the instance holds the private seed.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool HasPrivateSeed
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.HasPrivateSeed;
		}
	}

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
			return MLDsaKey<MLDsa65Parameters>.SubjectPublicKeyInfoLength;
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
	/// Generates a key pair from a new random private seed.
	/// </summary>
	/// <returns>An instance that holds the private seed, the private key and the public key.</returns>
	public static MLDsa65 GenerateKey()
	{
		MLDsa65 key = new();
		key._key.GenerateKey();
		return key;
	}

	/// <summary>
	/// Derives a key pair from <paramref name="source" /> with ML-DSA.KeyGen_internal (FIPS 204, Algorithm 6).
	/// </summary>
	/// <param name="source">The private seed ξ, exactly <see cref="PrivateSeedLength" /> bytes long.</param>
	/// <returns>An instance that holds the private seed, the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length.</exception>
	public static MLDsa65 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		MLDsa65 key = new();
		key._key.ImportPrivateSeed(source);
		return key;
	}

	/// <summary>
	/// Imports a private key.
	/// </summary>
	/// <remarks>The key is validated before use; implementation-owned key material is erased if it is invalid.</remarks>
	/// <param name="source">The private key, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the private key and the public key, but not the private seed.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a valid private key.</exception>
	public static MLDsa65 ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		MLDsa65 key = new();
		key._key.ImportPrivateKey(source);
		return key;
	}

	/// <summary>
	/// Imports a public key.
	/// </summary>
	/// <param name="source">The public key, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length.</exception>
	public static MLDsa65 ImportPublicKey(ReadOnlySpan<byte> source)
	{
		MLDsa65 key = new();
		key._key.ImportPublicKey(source);
		return key;
	}

	/// <inheritdoc />
	public static MLDsa65 ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		MLDsa65 key = new();
		key._key.ImportSubjectPublicKeyInfo(source);
		return key;
	}

	/// <inheritdoc />
	public static MLDsa65 ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		MLDsa65 key = new();
		key._key.ImportPkcs8PrivateKey(source);
		return key;
	}

	/// <summary>
	/// Writes the private seed.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="PrivateSeedLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private seed.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPrivateSeed(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPrivateSeed(destination);
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
	/// Signs <paramref name="message" /> with ML-DSA.Sign (FIPS 204, Algorithm 2).
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

	// ML-DSA.Sign with a given rnd, for known-answer tests.
	internal int Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> randomness, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.Sign(message, context, randomness, destination);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of <paramref name="message" /> with ML-DSA.Verify (FIPS 204, Algorithm 3).
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
	/// Signs the hash of a message with HashML-DSA.Sign (FIPS 204, Algorithm 4).
	/// </summary>
	/// <remarks>
	/// The hash algorithm needs a collision strength of at least 192 bits, that of ML-DSA-65: SHA-384, SHA-512, SHA3-384,
	/// SHA3-512, or SHAKE256 with 64 bytes of output. <paramref name="hash" /> may overlap <paramref name="destination" />.
	/// On failure, <paramref name="destination" /> remains unchanged.
	/// </remarks>
	/// <param name="hash">The hash of the message, as long as the output of the hash algorithm.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="SignatureLength" /> bytes long.</param>
	/// <param name="hashAlgorithmOid">The dotted-decimal OID of the hash algorithm.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns>The value of <see cref="SignatureLength" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="hashAlgorithmOid" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="hashAlgorithmOid" /> is not a supported hash algorithm, <paramref name="hash" /> has the wrong length,
	/// <paramref name="destination" /> is too short, or <paramref name="context" /> is too long.
	/// </exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int SignPreHash(ReadOnlySpan<byte> hash, Span<byte> destination, string hashAlgorithmOid, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.SignPreHash(hash, destination, hashAlgorithmOid, context);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of the hash of a message with HashML-DSA.Verify (FIPS 204, Algorithm 5).
	/// </summary>
	/// <remarks>The hash algorithms are those of <see cref="SignPreHash" />.</remarks>
	/// <param name="hash">The hash of the message, as long as the output of the hash algorithm.</param>
	/// <param name="signature">The signature.</param>
	/// <param name="hashAlgorithmOid">The dotted-decimal OID of the hash algorithm.</param>
	/// <param name="context">The context string, at most <see cref="MaxContextLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="hashAlgorithmOid" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="hashAlgorithmOid" /> is not a supported hash algorithm, <paramref name="hash" /> has the wrong length, or
	/// <paramref name="context" /> is too long.
	/// </exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool VerifyPreHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, string hashAlgorithmOid, ReadOnlySpan<byte> context = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.VerifyPreHash(hash, signature, hashAlgorithmOid, context);
	}

	/// <summary>
	/// Signs the message representative μ with ML-DSA.Sign_internal (FIPS 204, Algorithm 7), which then skips computing μ.
	/// </summary>
	/// <remarks>
	/// μ = H(tr ‖ M′, 64) for tr = H(pk, 64) and the M′ of ML-DSA.Sign or HashML-DSA.Sign; the caller computes it, so that the message need not
	/// pass through the instance. <paramref name="mu" /> may overlap <paramref name="destination" />. On failure,
	/// <paramref name="destination" /> remains unchanged.
	/// </remarks>
	/// <param name="mu">The message representative, exactly <see cref="MuLength" /> bytes long.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="SignatureLength" /> bytes long.</param>
	/// <returns>The value of <see cref="SignatureLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="mu" /> has the wrong length, or <paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int SignMu(ReadOnlySpan<byte> mu, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.SignMu(mu, destination);
	}

	// ML-DSA.Sign_internal after μ with a given rnd, for known-answer tests.
	internal int SignMu(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> randomness, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.SignMu(mu, randomness, destination);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of the message representative μ with ML-DSA.Verify_internal
	/// (FIPS 204, Algorithm 8), which then skips computing μ.
	/// </summary>
	/// <remarks>μ is that of <see cref="SignMu(ReadOnlySpan{byte}, Span{byte})" />.</remarks>
	/// <param name="mu">The message representative, exactly <see cref="MuLength" /> bytes long.</param>
	/// <param name="signature">The signature.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="mu" /> has the wrong length.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool VerifyMu(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.VerifyMu(mu, signature);
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return MLDsaKey<MLDsa65Parameters>.Supports(algorithm);
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return MLDsaKey<MLDsa65Parameters>.GetMaxSignatureLength(algorithm);
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
