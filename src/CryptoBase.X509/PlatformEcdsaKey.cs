namespace CryptoBase.X509;

/// <summary>
/// Provides <see cref="ISignatureKey" /> over a platform <see cref="ECDsa" /> key, such as one in a key store, smart card or TPM whose private key cannot be exported.
/// </summary>
/// <remarks>
/// <para>
/// The key must be on the curve P-256, P-384 or P-521 and hold the private key; the platform cannot report a missing private key, so <see cref="Sign" /> then throws <see cref="CryptographicException" />.
/// The instance supports <see cref="SignatureAlgorithm.EcdsaSha256" />, <see cref="SignatureAlgorithm.EcdsaSha384" /> and <see cref="SignatureAlgorithm.EcdsaSha512" />, and signs and verifies in DER through the platform.
/// Verification uses a copy of the public key, so it does not reach the key store or device, and it accepts only strict DER: the platform alone also accepts an INTEGER without the zero byte that its sign needs.
/// </para>
/// <para>
/// The private key is never exported: <see cref="Pkcs8PrivateKeyLength" /> and <see cref="ExportPkcs8PrivateKey" /> throw <see cref="InvalidOperationException" />.
/// Signing and verification may run concurrently on one instance; the instance passes one signing operation at a time to the platform, and likewise one verification.
/// </para>
/// </remarks>
public sealed class PlatformEcdsaKey : ISignatureKey
{
	private readonly ECDsa _key;
	private readonly ECDsa _publicKey;
	private readonly byte[] _subjectPublicKeyInfo;
	private readonly int _fieldLength;
	private readonly int _maxSignatureLength;
	private readonly Lock _signLock = new();
	private readonly Lock _verifyLock = new();
	private bool _disposed;

	/// <summary>
	/// Initializes an instance over a platform key, and takes ownership of it.
	/// </summary>
	/// <remarks>Once the constructor returns, the instance disposes <paramref name="key" /> when it is disposed; if the constructor throws, the caller still owns <paramref name="key" />.</remarks>
	/// <param name="key">The platform key.</param>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The SubjectPublicKeyInfo of <paramref name="key" /> is malformed.</exception>
	/// <exception cref="NotSupportedException"><paramref name="key" /> is not on P-256, P-384 or P-521 named by its OID.</exception>
	public PlatformEcdsaKey(ECDsa key)
	{
		ArgumentNullException.ThrowIfNull(key);

		byte[] subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();

		// The field length in bytes, and the longest DER signature, for each curve.
		(_fieldLength, _maxSignatureLength) = SubjectPublicKeyInfo.Decode(subjectPublicKeyInfo, nameof(key)).Algorithm.Encoded.Span switch
		{
			[0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => (32, 72),
			[0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22] => (48, 104),
			[0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23] => (66, 139),
			_ => throw new NotSupportedException("The key is not on P-256, P-384 or P-521.")
		};

		ECDsa publicKey = ECDsa.Create();

		try
		{
			publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
		}
		catch
		{
			publicKey.Dispose();
			throw;
		}

		_key = key;
		_publicKey = publicKey;
		_subjectPublicKeyInfo = subjectPublicKeyInfo;
	}

	/// <summary>
	/// Gets <see langword="true" />: the instance is for a key that holds the private key.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool HasPrivateKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return true;
		}
	}

	/// <inheritdoc />
	public int SubjectPublicKeyInfoLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _subjectPublicKeyInfo.Length;
		}
	}

	/// <summary>
	/// Throws <see cref="InvalidOperationException" />: the private key is not exportable.
	/// </summary>
	/// <exception cref="InvalidOperationException">Always, unless the instance has been disposed.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Pkcs8PrivateKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			throw NotExportable();
		}
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return algorithm is SignatureAlgorithm.EcdsaSha256 or SignatureAlgorithm.EcdsaSha384 or SignatureAlgorithm.EcdsaSha512;
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_ = HashOf(algorithm);
		return _maxSignatureLength;
	}

	/// <inheritdoc />
	public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		HashAlgorithmName hash = HashOf(algorithm);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, _maxSignatureLength, nameof(destination));

		// The platform writes to a buffer of its own, so that destination stays unchanged if it fails.
		Span<byte> signature = stackalloc byte[_maxSignatureLength];
		int written;

		lock (_signLock)
		{
			ObjectDisposedException.ThrowIf(_disposed, this);

			if (!_key.TrySignData(message, signature, hash, DSASignatureFormat.Rfc3279DerSequence, out written))
			{
				throw new CryptographicException("The signature is longer than the maximum for the curve.");
			}
		}

		signature.Slice(0, written).CopyTo(destination);
		return written;
	}

	/// <inheritdoc />
	public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		HashAlgorithmName hash = HashOf(algorithm);

		if (!IsStrictDer(signature))
		{
			return false;
		}

		lock (_verifyLock)
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _publicKey.VerifyData(message, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
		}
	}

	/// <inheritdoc />
	public int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, _subjectPublicKeyInfo.Length, nameof(destination));

		_subjectPublicKeyInfo.CopyTo(destination);
		return _subjectPublicKeyInfo.Length;
	}

	/// <summary>
	/// Throws <see cref="InvalidOperationException" />: the private key is not exportable.
	/// </summary>
	/// <param name="destination">The output buffer, which remains unchanged.</param>
	/// <returns>Never returns.</returns>
	/// <exception cref="InvalidOperationException">Always, unless the instance has been disposed.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		throw NotExportable();
	}

	/// <summary>
	/// Disposes the instance and the platform key.
	/// </summary>
	public void Dispose()
	{
		// Neither key is disposed while an operation uses it.
		lock (_signLock)
		{
			lock (_verifyLock)
			{
				if (_disposed)
				{
					return;
				}

				_disposed = true;
			}
		}

		_key.Dispose();
		_publicKey.Dispose();
	}

	private static HashAlgorithmName HashOf(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => HashAlgorithmName.SHA256,
			SignatureAlgorithm.EcdsaSha384 => HashAlgorithmName.SHA384,
			SignatureAlgorithm.EcdsaSha512 => HashAlgorithmName.SHA512,
			_ => throw new ArgumentException("The key does not support the signature algorithm.", nameof(algorithm))
		};
	}

	// A SEQUENCE of two minimal, nonnegative INTEGERs that fit the field, with nothing after it.
	private bool IsStrictDer(ReadOnlySpan<byte> signature)
	{
		try
		{
			AsnDecoder.ReadSequence(signature, AsnEncodingRules.DER, out int offset, out int length, out int consumed);
			ReadOnlySpan<byte> contents = signature.Slice(offset, length);
			return consumed == signature.Length && IsScalar(ref contents) && IsScalar(ref contents) && contents.IsEmpty;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// DER has already rejected a redundant leading byte.
	private bool IsScalar(ref ReadOnlySpan<byte> contents)
	{
		ReadOnlySpan<byte> value = AsnDecoder.ReadIntegerBytes(contents, AsnEncodingRules.DER, out int consumed);
		contents = contents.Slice(consumed);
		return value[0] < 0x80 && value.Length - (value[0] is 0 ? 1 : 0) <= _fieldLength;
	}

	private static InvalidOperationException NotExportable()
	{
		return new InvalidOperationException("The private key is not exportable.");
	}
}
