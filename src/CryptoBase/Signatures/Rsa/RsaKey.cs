using CryptoBase.Hashes.Sha2;

namespace CryptoBase.Signatures.Rsa;

/// <summary>
/// Provides RSA signatures: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017) with SHA-256, SHA-384 or SHA-512.
/// </summary>
/// <remarks>
/// <para>
/// The key signs and verifies with <see cref="SignatureAlgorithm.RsaPkcs1Sha256" /> to <see cref="SignatureAlgorithm.RsaPssSha512" />. RSASSA-PSS uses MGF1 with the message hash and a salt as long as the hash; it draws a new salt for each signature.
/// An algorithm whose encoded message does not fit the modulus (RFC 8017, Secs. 9.1.1 and 9.2) is not supported, and neither is one that the AlgorithmIdentifier of an imported key rules out. A signature is as long as the modulus.
/// </para>
/// <para>
/// Signing throws <see cref="CryptographicException" /> rather than return a signature that does not verify.
/// RSASSA-PKCS1-v1_5 signing writes a DigestInfo with NULL parameters, and verification also accepts one without parameters (RFC 5246, Sec. 4.7). RSASSA-PSS verification accepts only a salt as long as the hash.
/// Signing and verification may run concurrently on one instance.
/// </para>
/// <para>
/// The modulus must have 512 to 16384 bits, and the public exponent, odd and at least 3 (RFC 8017, Sec. 3.1), at most 33 bits. A private key has two primes; importing one checks that its values are consistent with each other and with the public key, but not that the primes are prime.
/// </para>
/// <para>
/// SubjectPublicKeyInfo and PKCS #8 name the algorithm rsaEncryption with NULL parameters (RFC 4055, Sec. 1.2), which allows every algorithm, or id-RSASSA-PSS (RFC 4055, Sec. 3.1), which allows RSASSA-PSS alone: with each hash if the parameters are absent, and otherwise with the hash that RSASSA-PSS-params name, if MGF1 names the same one and the hash is at least saltLength bytes long (RFC 4055, Sec. 3.3).
/// In RSASSA-PSS-params, a hash AlgorithmIdentifier may have NULL or absent parameters (RFC 4055, Sec. 2.1), and the trailer field must be 1 or absent. An instance exports the AlgorithmIdentifier of the key it imports unchanged; a generated key, and one imported from PKCS #1, has rsaEncryption.
/// </para>
/// <para>
/// A PKCS #8 export holds the RSAPrivateKey (RFC 8017, Appendix A.1.2) alone. A PKCS #8 import also accepts a key with the public key, but throws if it does not match. RSAPrivateKey must have version 0, for two primes; a multi-prime key throws <see cref="NotSupportedException" />.
/// </para>
/// </remarks>
public sealed class RsaKey : ISignatureKey<RsaKey>
{
	private static readonly byte[] RsaEncryption = RsaKeyDer.RsaEncryption.ToArray();

	private readonly RsaPublicOperation _publicKey;
	private readonly RsaPrivateOperation? _privateKey;
	private readonly byte[] _algorithmIdentifier;
	private readonly int _algorithms;
	private bool _disposed;

	// privateKey, if any, has publicKey, and the instance owns it.
	private RsaKey(RsaPublicOperation publicKey, RsaPrivateOperation? privateKey, byte[] algorithmIdentifier, int allowedAlgorithms)
	{
		_publicKey = publicKey;
		_privateKey = privateKey;
		_algorithmIdentifier = algorithmIdentifier;
		_algorithms = allowedAlgorithms & RsaAlgorithms.Fitting(publicKey.ModulusBits);
	}

	/// <summary>
	/// Gets the length of the modulus, in bits.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ModulusBits
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _publicKey.ModulusBits;
		}
	}

	/// <inheritdoc />
	public bool HasPrivateKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _privateKey is not null;
		}
	}

	/// <inheritdoc />
	public int SubjectPublicKeyInfoLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return KeyInfoDer.GetSubjectPublicKeyInfoLength(_algorithmIdentifier, RsaKeyDer.GetRsaPublicKeyLength(_publicKey));
		}
	}

	/// <inheritdoc />
	public int Pkcs8PrivateKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return KeyInfoDer.GetPrivateKeyInfoLength(_algorithmIdentifier, RsaKeyDer.GetRsaPrivateKeyLength(GetPrivateKey()));
		}
	}

	/// <summary>
	/// Gets the length of the RSAPublicKey that <see cref="ExportRsaPublicKey" /> writes, in bytes.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int RsaPublicKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return RsaKeyDer.GetRsaPublicKeyLength(_publicKey);
		}
	}

	/// <summary>
	/// Gets the length of the RSAPrivateKey that <see cref="ExportRsaPrivateKey" /> writes, in bytes.
	/// </summary>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int RsaPrivateKeyLength
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return RsaKeyDer.GetRsaPrivateKeyLength(GetPrivateKey());
		}
	}

	/// <summary>
	/// Generates a key pair with FIPS 186-5, Appendix A.1.3, from new random primes.
	/// </summary>
	/// <param name="modulusBits">The length of the modulus, in bits: a multiple of 8 from 2048 to 16384.</param>
	/// <param name="publicExponent">The public exponent: odd, above 2^16 and below 2^33.</param>
	/// <returns>An instance that holds the private key and the public key, whose AlgorithmIdentifier is rsaEncryption.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="modulusBits" /> is not a multiple of 8 from 2048 to 16384.</exception>
	/// <exception cref="ArgumentException"><paramref name="publicExponent" /> is even, at most 2^16, or at least 2^33.</exception>
	/// <exception cref="CryptographicException">Four runs in a row of FIPS 186-5, Appendix A.1.3, found no primes, which is vanishingly unlikely.</exception>
	public static RsaKey GenerateKey(int modulusBits, ulong publicExponent = 65537)
	{
		return Create(RsaPrivateOperation.Generate(modulusBits, publicExponent), RsaEncryption, RsaAlgorithms.All, default);
	}

	/// <summary>
	/// Imports a public key from a DER-encoded RSAPublicKey (RFC 8017, Appendix A.1.1).
	/// </summary>
	/// <param name="source">The RSAPublicKey, with nothing after it.</param>
	/// <returns>An instance that holds only the public key, whose AlgorithmIdentifier is rsaEncryption.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded RSAPublicKey, or holds an invalid key: its modulus is not odd, or its public exponent is not odd and at least 3.</exception>
	/// <exception cref="NotSupportedException">The modulus has fewer than 512 or more than 16384 bits, or the public exponent more than 33 bits.</exception>
	public static RsaKey ImportRsaPublicKey(ReadOnlySpan<byte> source)
	{
		return new RsaKey(RsaKeyDer.ReadRsaPublicKey(source), null, RsaEncryption, RsaAlgorithms.All);
	}

	/// <summary>
	/// Imports a private key from a DER-encoded RSAPrivateKey (RFC 8017, Appendix A.1.2).
	/// </summary>
	/// <param name="source">The RSAPrivateKey, with nothing after it.</param>
	/// <returns>An instance that holds the private key and the public key, whose AlgorithmIdentifier is rsaEncryption.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded RSAPrivateKey of version 0, or holds an invalid key.</exception>
	/// <exception cref="NotSupportedException">The key has more than two primes, its modulus has fewer than 512 or more than 16384 bits, or its public exponent more than 33 bits.</exception>
	public static RsaKey ImportRsaPrivateKey(ReadOnlySpan<byte> source)
	{
		return Create(RsaKeyDer.ReadRsaPrivateKey(source), RsaEncryption, RsaAlgorithms.All, default);
	}

	/// <inheritdoc />
	/// <exception cref="NotSupportedException">The modulus has fewer than 512 or more than 16384 bits, the public exponent has more than 33 bits, or the RSASSA-PSS parameters allow none of the algorithms.</exception>
	public static RsaKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		ReadOnlySpan<byte> algorithmIdentifier = RsaKeyDer.ReadKeyInfoAlgorithm(source, privateKey: false);
		int allowedAlgorithms = RsaKeyDer.GetAllowedAlgorithms(algorithmIdentifier);

		if (!KeyInfoDer.TryReadSubjectPublicKeyInfo(algorithmIdentifier, source, out ReadOnlySpan<byte> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		return new RsaKey(RsaKeyDer.ReadRsaPublicKey(publicKey), null, algorithmIdentifier.ToArray(), allowedAlgorithms);
	}

	/// <inheritdoc />
	/// <exception cref="NotSupportedException">The key has more than two primes, its modulus has fewer than 512 or more than 16384 bits, its public exponent has more than 33 bits, or the RSASSA-PSS parameters allow none of the algorithms.</exception>
	public static RsaKey ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
	{
		ReadOnlySpan<byte> algorithmIdentifier = RsaKeyDer.ReadKeyInfoAlgorithm(source, privateKey: true);
		int allowedAlgorithms = RsaKeyDer.GetAllowedAlgorithms(algorithmIdentifier);

		if (!KeyInfoDer.TryReadPrivateKeyInfo(algorithmIdentifier, source, out ReadOnlySpan<byte> privateKey, out ReadOnlySpan<byte> publicKey))
		{
			ThrowHelper.ThrowInvalidKey(nameof(source));
		}

		return Create(RsaKeyDer.ReadRsaPrivateKey(privateKey), algorithmIdentifier.ToArray(), allowedAlgorithms, publicKey);
	}

	/// <summary>
	/// Writes the public key as a DER-encoded RSAPublicKey (RFC 8017, Appendix A.1.1).
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="RsaPublicKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportRsaPublicKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, RsaKeyDer.GetRsaPublicKeyLength(_publicKey), nameof(destination));
		return RsaKeyDer.WriteRsaPublicKey(_publicKey, destination);
	}

	/// <summary>
	/// Writes the private key as a DER-encoded RSAPrivateKey (RFC 8017, Appendix A.1.2) of version 0.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="RsaPrivateKeyLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="InvalidOperationException">The instance does not hold the private key.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int ExportRsaPrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		RsaPrivateOperation privateKey = GetPrivateKey();
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, RsaKeyDer.GetRsaPrivateKeyLength(privateKey), nameof(destination));
		return RsaKeyDer.WriteRsaPrivateKey(privateKey, destination);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int ExportSubjectPublicKeyInfo(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		int publicKeyLength = RsaKeyDer.GetRsaPublicKeyLength(_publicKey);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, KeyInfoDer.GetSubjectPublicKeyInfoLength(_algorithmIdentifier, publicKeyLength), nameof(destination));

		Span<byte> publicKey = stackalloc byte[publicKeyLength];
		RsaKeyDer.WriteRsaPublicKey(_publicKey, publicKey);
		return KeyInfoDer.WriteSubjectPublicKeyInfo(_algorithmIdentifier, publicKey, destination);
	}

	/// <inheritdoc />
	public int ExportPkcs8PrivateKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		RsaPrivateOperation privateKey = GetPrivateKey();
		int privateKeyLength = RsaKeyDer.GetRsaPrivateKeyLength(privateKey);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, KeyInfoDer.GetPrivateKeyInfoLength(_algorithmIdentifier, privateKeyLength), nameof(destination));

		using CryptoBuffer<byte> rsaPrivateKey = new(privateKeyLength);
		RsaKeyDer.WriteRsaPrivateKey(privateKey, rsaPrivateKey.Span);
		return KeyInfoDer.WritePrivateKeyInfo(_algorithmIdentifier, rsaPrivateKey.Span, destination);
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return (_algorithms & RsaAlgorithms.Bit(algorithm)) is not 0;
	}

	/// <inheritdoc />
	/// <returns>The length of the modulus, in bytes, which every signature has.</returns>
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfUnsupported(algorithm);
		return _publicKey.ModulusLength;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		RsaPrivateOperation privateKey = GetSigningKey(algorithm, destination);

		Span<byte> salt = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, RsaAlgorithms.IsPss(algorithm) ? RsaAlgorithms.HashLength(algorithm) : 0);
		SystemRandom.Fill(salt);
		return SignCore(privateKey, algorithm, message, salt, destination);
	}

	// Sign with the salt given rather than drawn, as long as the hash for RSASSA-PSS and empty for RSASSA-PKCS1-v1_5, for known-answer tests.
	internal int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> salt, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		RsaPrivateOperation privateKey = GetSigningKey(algorithm, destination);
		ArgumentOutOfRangeException.ThrowIfNotEqual(salt.Length, RsaAlgorithms.IsPss(algorithm) ? RsaAlgorithms.HashLength(algorithm) : 0, nameof(salt));
		return SignCore(privateKey, algorithm, message, salt, destination);
	}

	/// <inheritdoc />
	public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfUnsupported(algorithm);

		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => VerifyPkcs1Core<Sha256Core>(RsaPadding.Sha256DigestInfo, RsaPadding.Sha256DigestInfoWithoutParameters, message, signature),
			SignatureAlgorithm.RsaPkcs1Sha384 => VerifyPkcs1Core<Sha384Core>(RsaPadding.Sha384DigestInfo, RsaPadding.Sha384DigestInfoWithoutParameters, message, signature),
			SignatureAlgorithm.RsaPkcs1Sha512 => VerifyPkcs1Core<Sha512Core>(RsaPadding.Sha512DigestInfo, RsaPadding.Sha512DigestInfoWithoutParameters, message, signature),
			SignatureAlgorithm.RsaPssSha256 => VerifyPssCore<Sha256Core>(message, signature, Sha256Core.HashLength),
			SignatureAlgorithm.RsaPssSha384 => VerifyPssCore<Sha384Core>(message, signature, Sha384Core.HashLength),
			_ => VerifyPssCore<Sha512Core>(message, signature, Sha512Core.HashLength)
		};
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_privateKey?.Dispose();
		_disposed = true;
	}

	// An instance that owns privateKey, whose public key must equal expectedPublicKey, an RSAPublicKey, unless it is empty; privateKey is disposed if this throws.
	[SkipLocalsInit]
	private static RsaKey Create(RsaPrivateOperation privateKey, byte[] algorithmIdentifier, int allowedAlgorithms, ReadOnlySpan<byte> expectedPublicKey)
	{
		try
		{
			if (!expectedPublicKey.IsEmpty)
			{
				Span<byte> publicKey = stackalloc byte[RsaKeyDer.GetRsaPublicKeyLength(privateKey.PublicKey)];
				RsaKeyDer.WriteRsaPublicKey(privateKey.PublicKey, publicKey);

				if (!expectedPublicKey.SequenceEqual(publicKey))
				{
					ThrowHelper.ThrowInvalidKey("source");
				}
			}

			return new RsaKey(privateKey.PublicKey, privateKey, algorithmIdentifier, allowedAlgorithms);
		}
		catch
		{
			privateKey.Dispose();
			throw;
		}
	}

	// The algorithm is supported.
	private static int SignCore(RsaPrivateOperation privateKey, SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> salt, Span<byte> destination)
	{
		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => SignPkcs1Core<Sha256Core>(privateKey, RsaPadding.Sha256DigestInfo, message, destination),
			SignatureAlgorithm.RsaPkcs1Sha384 => SignPkcs1Core<Sha384Core>(privateKey, RsaPadding.Sha384DigestInfo, message, destination),
			SignatureAlgorithm.RsaPkcs1Sha512 => SignPkcs1Core<Sha512Core>(privateKey, RsaPadding.Sha512DigestInfo, message, destination),
			SignatureAlgorithm.RsaPssSha256 => SignPssCore<Sha256Core>(privateKey, message, salt, destination),
			SignatureAlgorithm.RsaPssSha384 => SignPssCore<Sha384Core>(privateKey, message, salt, destination),
			_ => SignPssCore<Sha512Core>(privateKey, message, salt, destination)
		};
	}

	// RSASSA-PKCS1-V1_5-SIGN (RFC 8017, Sec. 8.2.1) with a DigestInfo with NULL parameters; destination is at least k bytes long, and receives the signature only once it has been checked.
	[SkipLocalsInit]
	private static int SignPkcs1Core<THash>(RsaPrivateOperation privateKey, ReadOnlySpan<byte> digestInfo, ReadOnlySpan<byte> message, Span<byte> destination) where THash : unmanaged, IHashCore<THash>
	{
		int length = privateKey.PublicKey.ModulusLength;
		Span<byte> hash = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, THash.HashLength);
		RsaPadding.Hash<THash>(message, hash);

		Span<byte> encoded = stackalloc byte[length];
		RsaPadding.EncodePkcs1(digestInfo, hash, encoded);
		privateKey.Apply(encoded, destination.Slice(0, length));
		return length;
	}

	// RSASSA-PSS-SIGN (RFC 8017, Sec. 8.1.1) with a salt that fits; destination as for RSASSA-PKCS1-v1_5.
	[SkipLocalsInit]
	private static int SignPssCore<THash>(RsaPrivateOperation privateKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> salt, Span<byte> destination) where THash : unmanaged, IHashCore<THash>
	{
		int length = privateKey.PublicKey.ModulusLength;
		Span<byte> hash = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, THash.HashLength);
		RsaPadding.Hash<THash>(message, hash);

		Span<byte> encoded = stackalloc byte[length];
		RsaPadding.EncodePss<THash>(hash, salt, privateKey.PublicKey.ModulusBits, encoded);
		privateKey.Apply(encoded, destination.Slice(0, length));
		return length;
	}

	// RSASSA-PKCS1-V1_5-VERIFY (RFC 8017, Sec. 8.2.2), for a DigestInfo with NULL parameters or without them.
	[SkipLocalsInit]
	private bool VerifyPkcs1Core<THash>(ReadOnlySpan<byte> digestInfo, ReadOnlySpan<byte> digestInfoWithoutParameters, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) where THash : unmanaged, IHashCore<THash>
	{
		// Steps 1 and 2: RSAVP1 (Sec. 5.2.2) on a signature as long as the modulus, whose representative is below it.
		int length = _publicKey.ModulusLength;
		Span<byte> encoded = stackalloc byte[length];

		if (signature.Length != length || !_publicKey.TryApply(signature, encoded))
		{
			return false;
		}

		// Steps 3 and 4.
		Span<byte> hash = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, THash.HashLength);
		RsaPadding.Hash<THash>(message, hash);
		return RsaPadding.IsPkcs1Encoding(encoded, digestInfo, hash) || RsaPadding.IsPkcs1Encoding(encoded, digestInfoWithoutParameters, hash);
	}

	// RSASSA-PSS-VERIFY (RFC 8017, Sec. 8.1.2).
	[SkipLocalsInit]
	private bool VerifyPssCore<THash>(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, int saltLength) where THash : unmanaged, IHashCore<THash>
	{
		// Steps 1 and 2a to 2b, as for RSASSA-PKCS1-v1_5; EMSA-PSS-VERIFY takes the I2OSP of step 2c.
		int length = _publicKey.ModulusLength;
		Span<byte> encoded = stackalloc byte[length];

		if (signature.Length != length || !_publicKey.TryApply(signature, encoded))
		{
			return false;
		}

		Span<byte> hash = stackalloc byte[RsaPadding.MaxHashLength].Slice(0, THash.HashLength);
		RsaPadding.Hash<THash>(message, hash);
		return RsaPadding.IsPssEncoding<THash>(hash, encoded, _publicKey.ModulusBits, saltLength);
	}

	private RsaPrivateOperation GetPrivateKey()
	{
		if (_privateKey is null)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		return _privateKey;
	}

	private RsaPrivateOperation GetSigningKey(SignatureAlgorithm algorithm, Span<byte> destination)
	{
		ThrowIfUnsupported(algorithm);
		RsaPrivateOperation privateKey = GetPrivateKey();
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, _publicKey.ModulusLength, nameof(destination));
		return privateKey;
	}

	private void ThrowIfUnsupported(SignatureAlgorithm algorithm)
	{
		if ((_algorithms & RsaAlgorithms.Bit(algorithm)) is 0)
		{
			ThrowHelper.ThrowUnsupportedSignatureAlgorithm(nameof(algorithm));
		}
	}
}
