using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.SM2;

/// <summary>
/// Provides SM2 (GB/T 32918-2016) over its recommended curve: the digital signature algorithm with SM3 and public key encryption, as well as the static key of <see cref="SM2KeyExchange" />.
/// </summary>
/// <remarks>
/// <para>
/// The private key d is big-endian and must lie in [1, n − 2]. The public key is in the uncompressed encoding and must lie on the curve.
/// An instance that holds only the public key verifies and encrypts; signing, decryption and the key exchange need the private key. Signing, verification, encryption and decryption may run concurrently on one instance.
/// </para>
/// <para>
/// A signature is SEQUENCE { r INTEGER, s INTEGER } in DER, and verification rejects any other encoding. The ID of the signer goes into the signature: <see cref="SignatureAlgorithm.SM2SM3" /> and the methods without an ID take <see cref="DefaultId" />, and the overloads with an ID take any ID of up to <see cref="MaxIdLength" /> bytes, the empty one included.
/// Signing a message twice gives two different signatures.
/// </para>
/// <para>
/// To verify many signatures, encrypt many messages or exchange many keys with one key, keep one instance rather than import the key for each.
/// </para>
/// <para>
/// Encryption writes C1 ‖ C3 ‖ C2 of GB/T 32918.4-2016 with C1 uncompressed, or the SM2Cipher of GB/T 35276-2017 in DER. The plaintext must not be empty, and encrypting a message twice gives two different ciphertexts. Decryption rejects other point encodings of C1, an empty C2 and an SM2Cipher in any encoding but DER.
/// </para>
/// <para>
/// SubjectPublicKeyInfo and PKCS #8 have the algorithm id-ecPublicKey with the named curve 1.2.156.10197.1.301 and hold the public key uncompressed; other parameters and point encodings are rejected. A PKCS #8 export holds the private key, the curve and the public key. A PKCS #8 import accepts a key without the curve or the public key, but rejects either, in the inner or the outer structure, if it does not match the private key.
/// </para>
/// </remarks>
public sealed class SM2Key : ISignatureKey<SM2Key>
{
	private SM2KeyState _key;
	private bool _disposed;

	private SM2Key() { }

	/// <summary>
	/// Gets the length of the private key, in bytes.
	/// </summary>
	public static int PrivateKeyLength => SM2KeyState.PrivateKeyLength;

	/// <summary>
	/// Gets the length of the public key in the uncompressed encoding, in bytes.
	/// </summary>
	public static int PublicKeyLength => SM2KeyState.PublicKeyLength;

	/// <summary>
	/// Gets the length of the longest signature, in bytes.
	/// </summary>
	public static int MaxSignatureLength => SM2KeyState.MaxSignatureLength;

	/// <summary>
	/// Gets the maximum length of an ID, in bytes.
	/// </summary>
	public static int MaxIdLength => SM2KeyState.MaxIdLength;

	/// <summary>
	/// Gets the default ID of GB/T 35276-2017, the ASCII string "1234567812345678".
	/// </summary>
	public static ReadOnlySpan<byte> DefaultId => SM2KeyState.DefaultId;

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
			return _key.SubjectPublicKeyInfoLength;
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

	internal static ReadOnlySpan<byte> AlgorithmIdentifier => SM2KeyState.AlgorithmIdentifier;

	/// <summary>
	/// Gets the length of the ciphertext C1 ‖ C3 ‖ C2 that <see cref="Encrypt(ReadOnlySpan{byte}, Span{byte})" /> writes.
	/// </summary>
	/// <param name="plaintextLength">The length of the plaintext, in bytes.</param>
	/// <returns>The length of the ciphertext, in bytes, 97 bytes longer than the plaintext.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="plaintextLength" /> is not positive or gives a ciphertext longer than <see cref="int.MaxValue" />.</exception>
	public static int GetCiphertextLength(int plaintextLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(plaintextLength);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(plaintextLength, int.MaxValue - SM2KeyState.CiphertextOverhead);

		return SM2KeyState.CiphertextOverhead + plaintextLength;
	}

	/// <summary>
	/// Gets the length of the longest SM2Cipher that <see cref="EncryptDer(ReadOnlySpan{byte}, Span{byte})" /> writes.
	/// </summary>
	/// <param name="plaintextLength">The length of the plaintext, in bytes.</param>
	/// <returns>The maximum length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="plaintextLength" /> is not positive or gives a ciphertext longer than <see cref="int.MaxValue" />.</exception>
	public static int GetMaxDerCiphertextLength(int plaintextLength)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(plaintextLength);

		int length = SM2CipherDer.GetMaxLength(plaintextLength);

		if (length < 0)
		{
			throw new ArgumentOutOfRangeException(nameof(plaintextLength), plaintextLength, "The ciphertext would be longer than int.MaxValue bytes.");
		}

		return length;
	}

	/// <summary>
	/// Generates a key pair from a new random private key.
	/// </summary>
	/// <returns>An instance that holds the private key and the public key.</returns>
	public static SM2Key GenerateKey()
	{
		return GenerateKey(SystemRandom.Fill);
	}

	/// <summary>
	/// Imports a private key.
	/// </summary>
	/// <remarks>Implementation-owned key material is erased if the key is invalid.</remarks>
	/// <param name="source">The private key as big-endian bytes, exactly <see cref="PrivateKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds the private key and the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not in [1, n − 2].</exception>
	public static SM2Key ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		SM2Key key = new();
		key._key.ImportPrivateKey(source);
		return key;
	}

	/// <summary>
	/// Imports a public key.
	/// </summary>
	/// <param name="source">The public key in the uncompressed encoding, exactly <see cref="PublicKeyLength" /> bytes long.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> has the wrong length or is not a point on the curve.</exception>
	public static SM2Key ImportPublicKey(ReadOnlySpan<byte> source)
	{
		SM2Key key = new();
		key._key.ImportPublicKey(source);
		return key;
	}

	/// <inheritdoc />
	public static SM2Key ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		SM2Key key = new();
		key._key.ImportSubjectPublicKeyInfo(source);
		return key;
	}

	/// <inheritdoc />
	public static SM2Key ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		SM2Key key = new();
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
	/// Signs <paramref name="message" /> with SM2 and SM3 (GB/T 32918.2-2016, Sec. 6.1) and the ID <see cref="DefaultId" />.
	/// </summary>
	/// <remarks><paramref name="message" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="message">The message.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="MaxSignatureLength" /> bytes long.</param>
	/// <returns>The length of the signature, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Sign(ReadOnlySpan<byte> message, Span<byte> destination)
	{
		return Sign(message, destination, DefaultId);
	}

	/// <summary>
	/// Signs <paramref name="message" /> with SM2 and SM3 (GB/T 32918.2-2016, Sec. 6.1) and the ID of the signer.
	/// </summary>
	/// <remarks><paramref name="message" /> and <paramref name="id" /> may overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="message">The message.</param>
	/// <param name="destination">The buffer that receives the signature, at least <see cref="MaxSignatureLength" /> bytes long.</param>
	/// <param name="id">The ID of the signer, at most <see cref="MaxIdLength" /> bytes long, which a verifier needs as well.</param>
	/// <returns>The length of the signature, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short, or <paramref name="id" /> is too long.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Sign(ReadOnlySpan<byte> message, Span<byte> destination, ReadOnlySpan<byte> id)
	{
		ThrowIfCannotSign(destination, id);

		return _key.Sign(message, id, destination);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of <paramref name="message" /> with SM2 and SM3 (GB/T 32918.2-2016, Sec. 7.1) and the ID <see cref="DefaultId" />.
	/// </summary>
	/// <param name="message">The message.</param>
	/// <param name="signature">The signature in DER.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		return Verify(message, signature, DefaultId);
	}

	/// <summary>
	/// Verifies that <paramref name="signature" /> is a signature of <paramref name="message" /> with SM2 and SM3 (GB/T 32918.2-2016, Sec. 7.1) and the ID of the signer.
	/// </summary>
	/// <param name="message">The message.</param>
	/// <param name="signature">The signature in DER.</param>
	/// <param name="id">The ID of the signer, at most <see cref="MaxIdLength" /> bytes long.</param>
	/// <returns><see langword="true" /> if the signature is valid; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="id" /> is too long.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> id)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		SM2KeyState.ThrowIfInvalidId(id, nameof(id));

		return _key.Verify(message, signature, id);
	}

	/// <inheritdoc />
	/// <remarks>The key supports <see cref="SignatureAlgorithm.SM2SM3" /> alone.</remarks>
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return SM2KeyState.Supports(algorithm);
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		SM2KeyState.ThrowIfUnsupported(algorithm);

		return MaxSignatureLength;
	}

	/// <inheritdoc />
	public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		SM2KeyState.ThrowIfUnsupported(algorithm);

		return Sign(message, destination);
	}

	/// <inheritdoc />
	public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		SM2KeyState.ThrowIfUnsupported(algorithm);

		return Verify(message, signature);
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> into C1 ‖ C3 ‖ C2 (GB/T 32918.4-2016, Sec. 6.1), with C1 uncompressed.
	/// </summary>
	/// <remarks><paramref name="plaintext" /> must not overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="plaintext">The plaintext, which must not be empty.</param>
	/// <param name="destination">The buffer that receives the ciphertext, at least <see cref="GetCiphertextLength" /> bytes long.</param>
	/// <returns>The length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="plaintext" /> is empty or too long, or <paramref name="destination" /> is too short or overlaps <paramref name="plaintext" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination)
	{
		return Encrypt(plaintext, destination, SystemRandom.Fill);
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" /> into the DER of an SM2Cipher (GB/T 35276-2017), which holds C1, C3 and C2 (GB/T 32918.4-2016, Sec. 6.1).
	/// </summary>
	/// <remarks><paramref name="plaintext" /> must not overlap <paramref name="destination" />. On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="plaintext">The plaintext, which must not be empty.</param>
	/// <param name="destination">The buffer that receives the ciphertext, at least <see cref="GetMaxDerCiphertextLength" /> bytes long.</param>
	/// <returns>The length of the ciphertext, in bytes.</returns>
	/// <exception cref="ArgumentException"><paramref name="plaintext" /> is empty or too long, or <paramref name="destination" /> is too short or overlaps <paramref name="plaintext" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int EncryptDer(ReadOnlySpan<byte> plaintext, Span<byte> destination)
	{
		return EncryptDer(plaintext, destination, SystemRandom.Fill);
	}

	/// <summary>
	/// Decrypts a ciphertext C1 ‖ C3 ‖ C2 (GB/T 32918.4-2016, Sec. 7.1), with C1 uncompressed.
	/// </summary>
	/// <remarks>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> is too short to hold a plaintext, C1 is not a point on the curve or C3 does not match. It then writes nothing to <paramref name="destination" />, which may overlap <paramref name="ciphertext" />.
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="destination">The buffer that receives the plaintext, at least as long as the plaintext: 97 bytes shorter than <paramref name="ciphertext" />.</param>
	/// <param name="bytesWritten">When this method returns <see langword="true" />, the length of the plaintext; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the ciphertext was decrypted; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int bytesWritten)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfNoPrivateKey();

		bytesWritten = 0;

		if (ciphertext.Length <= SM2KeyState.CiphertextOverhead)
		{
			return false;
		}

		int length = ciphertext.Length - SM2KeyState.CiphertextOverhead;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		if (!_key.Decrypt(ciphertext, destination))
		{
			return false;
		}

		bytesWritten = length;
		return true;
	}

	/// <summary>
	/// Decrypts the DER of an SM2Cipher (GB/T 35276-2017), which holds C1, C3 and C2 (GB/T 32918.4-2016, Sec. 7.1).
	/// </summary>
	/// <remarks>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> is not the DER of an SM2Cipher with a CipherText of at least one byte, C1 is not a point on the curve or C3 does not match. It then writes nothing to <paramref name="destination" />, which may overlap <paramref name="ciphertext" />.
	/// </remarks>
	/// <param name="ciphertext">The ciphertext.</param>
	/// <param name="destination">The buffer that receives the plaintext, at least as long as the CipherText of the SM2Cipher; a buffer as long as <paramref name="ciphertext" /> suffices.</param>
	/// <param name="bytesWritten">When this method returns <see langword="true" />, the length of the plaintext; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the ciphertext was decrypted; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[SkipLocalsInit]
	public bool TryDecryptDer(ReadOnlySpan<byte> ciphertext, Span<byte> destination, out int bytesWritten)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfNoPrivateKey();

		bytesWritten = 0;
		Span<byte> c1 = stackalloc byte[PublicKeyLength];

		if (!SM2CipherDer.TryRead(ciphertext, c1, out ReadOnlySpan<byte> c3, out ReadOnlySpan<byte> c2) || c2.IsEmpty)
		{
			return false;
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, c2.Length, nameof(destination));

		if (!_key.Decrypt(c1, c3, c2, destination))
		{
			return false;
		}

		bytesWritten = c2.Length;
		return true;
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

	// The state of the key of a party to SM2KeyExchange, or of the static key of its peer.
	internal ref SM2KeyState GetState()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return ref _key;
	}

	internal static SM2Key GenerateKey(Action<Span<byte>> fill)
	{
		SM2Key key = new();
		key._key.GenerateKey(fill);
		return key;
	}

	internal int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination, Action<Span<byte>> fill)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		int length = GetCheckedCiphertextLength(plaintext, destination);
		_key.Encrypt(plaintext, destination.Slice(0, length), fill);
		return length;
	}

	internal int EncryptDer(ReadOnlySpan<byte> plaintext, Span<byte> destination, Action<Span<byte>> fill)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (plaintext.IsEmpty)
		{
			ThrowEmptyPlaintext(nameof(plaintext));
		}

		int maxLength = SM2CipherDer.GetMaxLength(plaintext.Length);

		if (maxLength < 0)
		{
			ThrowPlaintextTooLong(nameof(plaintext));
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, maxLength, nameof(destination));

		if (plaintext.Overlaps(destination))
		{
			ThrowHelper.ThrowInputOutputOverlap(nameof(destination));
		}

		return _key.EncryptDer(plaintext, destination, fill);
	}

	// The length of the ciphertext of Encrypt, once its arguments pass the checks.
	private static int GetCheckedCiphertextLength(ReadOnlySpan<byte> plaintext, Span<byte> destination)
	{
		if (plaintext.IsEmpty)
		{
			ThrowEmptyPlaintext(nameof(plaintext));
		}

		if (plaintext.Length > int.MaxValue - SM2KeyState.CiphertextOverhead)
		{
			ThrowPlaintextTooLong(nameof(plaintext));
		}

		int length = SM2KeyState.CiphertextOverhead + plaintext.Length;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		if (plaintext.Overlaps(destination))
		{
			ThrowHelper.ThrowInputOutputOverlap(nameof(destination));
		}

		return length;
	}

	[DoesNotReturn]
	private static void ThrowEmptyPlaintext(string paramName)
	{
		throw new ArgumentException("The plaintext must not be empty.", paramName);
	}

	[DoesNotReturn]
	private static void ThrowPlaintextTooLong(string paramName)
	{
		throw new ArgumentException("The ciphertext would be longer than int.MaxValue bytes.", paramName);
	}

	private void ThrowIfNoPrivateKey()
	{
		if (!_key.HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}
	}

	private void ThrowIfCannotSign(Span<byte> destination, ReadOnlySpan<byte> id)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfNoPrivateKey();
		SM2KeyState.ThrowIfInvalidId(id, nameof(id));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MaxSignatureLength, nameof(destination));
	}
}
