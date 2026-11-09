using System.Buffers.Binary;
using System.Numerics;

namespace CryptoBase.X509;

/// <summary>
/// Provides <see cref="ISignatureKey" /> over a platform <see cref="RSA" /> key, such as one in a key store, smart card or TPM whose private key cannot be exported, or over an RSA public key alone.
/// </summary>
/// <remarks>
/// <para>
/// The instance signs and verifies with RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017) with SHA-256, SHA-384 or SHA-512: <see cref="SignatureAlgorithm.RsaPkcs1Sha256" /> to <see cref="SignatureAlgorithm.RsaPssSha512" />. RSASSA-PSS uses MGF1 with the message hash and a salt as long as the hash.
/// An algorithm whose encoded message does not fit the modulus (RFC 8017, Secs. 9.1.1 and 9.2) is not supported, and neither is one that the constructor finds or is told the key does not make.
/// </para>
/// <para>
/// The platform signs, and the instance verifies each signature before it returns it, so a key that signs otherwise, such as with another salt length, throws <see cref="CryptographicException" /> rather than giving a signature that does not verify.
/// Verification is managed and never reaches the platform, so it gives the same result on every platform: RSASSA-PKCS1-v1_5 as RFC 8017, Sec. 8.2.2, describes, comparing the encoded message byte for byte with the one expected, whose DigestInfo has NULL or, as TLS 1.2 also requires a verifier to accept (RFC 5246, Sec. 4.7), absent parameters; and RSASSA-PSS with EMSA-PSS-VERIFY (RFC 8017, Sec. 9.1.2) and a salt as long as the hash.
/// It handles public data alone, so it does not take constant time; its work is bounded by the key, whose modulus must have 512 to 16384 bits and whose public exponent, odd and at least 3 (RFC 8017, Sec. 3.1), must have at most 33 bits.
/// </para>
/// <para>
/// The private key is never exported: <see cref="Pkcs8PrivateKeyLength" /> and <see cref="ExportPkcs8PrivateKey" /> throw <see cref="InvalidOperationException" />.
/// Signing and verification may run concurrently on one instance; the instance passes one signing operation at a time to the platform.
/// </para>
/// </remarks>
public sealed class PlatformRsaKey : ISignatureKey
{
	private const int MinModulusBits = 512;
	private const int MaxModulusBits = 16384;
	private const int MaxPublicExponentBits = 33;
	private const int MaxHashLength = 64;

	private static readonly SignatureAlgorithm[] AllAlgorithms =
	[
		SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512,
		SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512
	];

	private static readonly SignatureAlgorithm[] Pkcs1Algorithms = [SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512];
	private static readonly SignatureAlgorithm[] PssAlgorithms = [SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512];

	private readonly RSA? _key;
	private readonly RsaPublicKey _publicKey;
	private readonly byte[] _subjectPublicKeyInfo;
	private readonly SignatureAlgorithm[] _algorithms;
	private readonly Lock _signLock = new();
	private bool _disposed;

	/// <summary>
	/// Initializes an instance over a platform key, takes ownership of it, and signs with it to learn whether it makes RSASSA-PSS signatures.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The constructor signs a fixed message with <see cref="SignatureAlgorithm.RsaPssSha256" /> and verifies the signature. If that fails, or the modulus is too short for it, it signs with <see cref="SignatureAlgorithm.RsaPkcs1Sha256" /> instead, and the instance supports RSASSA-PKCS1-v1_5 alone, as a smart card or TPM that lacks RSASSA-PSS needs.
	/// A key that makes the first signature is taken to make RSASSA-PKCS1-v1_5 signatures too, and a key that makes either one is taken to make it with SHA-384 and SHA-512 as well; a hash that a device lacks fails in <see cref="Sign" />.
	/// </para>
	/// <para>
	/// These signatures have the side effects of any other: a key store or device may ask the user for a PIN or consent, which may then be cached, and may count or log them. A first signature that fails for another reason, such as a cancelled prompt, also counts as a lack of RSASSA-PSS if the second succeeds.
	/// <see cref="PlatformRsaKey(RSA, ReadOnlySpan{SignatureAlgorithm})" /> takes the algorithms from the caller instead and signs nothing.
	/// </para>
	/// <para>
	/// Once the constructor returns, the instance disposes <paramref name="key" /> when it is disposed; if the constructor throws, the caller still owns <paramref name="key" />.
	/// </para>
	/// </remarks>
	/// <param name="key">The platform key, which must hold the private key.</param>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The public key of <paramref name="key" /> is invalid: its modulus is not odd, or its public exponent is not odd and at least 3.</exception>
	/// <exception cref="NotSupportedException">The modulus of <paramref name="key" /> has fewer than 512 or more than 16384 bits, or its public exponent more than 33 bits.</exception>
	/// <exception cref="CryptographicException">The platform fails to export the public key, or <paramref name="key" /> fails to sign with both paddings, as it does without the private key.</exception>
	public PlatformRsaKey(RSA key) : this(key, ExportPublicKey(key))
	{
		_algorithms = Probe(key, _publicKey);
	}

	/// <summary>
	/// Initializes an instance over a platform key that signs with the algorithms the caller names, and takes ownership of it.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The constructor signs nothing, so the key store or device is first used by <see cref="Sign" />, which throws <see cref="CryptographicException" /> if the key fails to make a signature with an algorithm named here.
	/// The instance supports those of <paramref name="algorithms" /> that the modulus fits. The platform cannot report a missing private key, so <see cref="Sign" /> then throws <see cref="CryptographicException" /> as well.
	/// </para>
	/// <para>
	/// Once the constructor returns, the instance disposes <paramref name="key" /> when it is disposed; if the constructor throws, the caller still owns <paramref name="key" />.
	/// </para>
	/// </remarks>
	/// <param name="key">The platform key, which must hold the private key.</param>
	/// <param name="algorithms">The algorithms that the key signs with, each one of <see cref="SignatureAlgorithm.RsaPkcs1Sha256" /> to <see cref="SignatureAlgorithm.RsaPssSha512" />; the instance keeps a copy.</param>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException">The public key of <paramref name="key" /> is invalid: its modulus is not odd, or its public exponent is not odd and at least 3; or <paramref name="algorithms" /> holds another value.</exception>
	/// <exception cref="NotSupportedException">The modulus of <paramref name="key" /> has fewer than 512 or more than 16384 bits, or its public exponent more than 33 bits.</exception>
	/// <exception cref="CryptographicException">The platform fails to export the public key.</exception>
	public PlatformRsaKey(RSA key, ReadOnlySpan<SignatureAlgorithm> algorithms) : this(key, ExportPublicKey(key))
	{
		foreach (SignatureAlgorithm algorithm in algorithms)
		{
			if (Array.IndexOf(AllAlgorithms, algorithm) < 0)
			{
				throw new ArgumentException("The algorithms include one that is not RSASSA-PKCS1-v1_5 or RSASSA-PSS with SHA-256, SHA-384 or SHA-512.", nameof(algorithms));
			}
		}

		_algorithms = Supported(algorithms, _publicKey);
	}

	// key stays with the caller until the public constructor returns.
	private PlatformRsaKey(RSA key, (RsaPublicKey PublicKey, byte[] SubjectPublicKeyInfo) exported)
	{
		_key = key;
		(_publicKey, _subjectPublicKeyInfo) = exported;
		_algorithms = [];
	}

	private PlatformRsaKey(RsaPublicKey publicKey, byte[] subjectPublicKeyInfo, SignatureAlgorithm[] algorithms)
	{
		_publicKey = publicKey;
		_subjectPublicKeyInfo = subjectPublicKeyInfo;
		_algorithms = algorithms;
	}

	/// <summary>
	/// Gets a value that indicates whether the instance holds the private key: <see langword="true" /> over a platform key, and <see langword="false" /> for a key that <see cref="ImportSubjectPublicKeyInfo" /> imports.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool HasPrivateKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key is not null;
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
	/// Throws <see cref="InvalidOperationException" />: the private key is not exportable, or the instance does not hold it.
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

	// The DER encoding of the DigestInfo of each hash up to the hash value, with NULL parameters (RFC 8017, Sec. 9.2, Note 1).
	private static ReadOnlySpan<byte> Sha256DigestInfo => [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

	private static ReadOnlySpan<byte> Sha384DigestInfo => [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];

	private static ReadOnlySpan<byte> Sha512DigestInfo => [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

	// The same without parameters.
	private static ReadOnlySpan<byte> Sha256DigestInfoWithoutParameters => [0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20];

	private static ReadOnlySpan<byte> Sha384DigestInfoWithoutParameters => [0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30];

	private static ReadOnlySpan<byte> Sha512DigestInfoWithoutParameters => [0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40];

	// rsaEncryption with the NULL parameters that RFC 4055, Sec. 1.2, requires.
	private static ReadOnlySpan<byte> RsaEncryption => [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];

	private static ReadOnlySpan<byte> ProbeMessage => "CryptoBase.X509.PlatformRsaKey"u8;

	/// <summary>
	/// Imports an RSA public key from a DER-encoded SubjectPublicKeyInfo (RFC 5280), for verification alone.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The algorithm must be rsaEncryption with NULL parameters (RFC 4055, Sec. 1.2), which allows every algorithm that the modulus fits, or id-RSASSA-PSS (RFC 4055, Sec. 3.1), which allows RSASSA-PSS alone: with each hash if the parameters are absent, and otherwise with the one hash that RSASSA-PSS-params name for the hash and for MGF1, if they name the same one, and if its length is at least their saltLength, as RFC 4055, Sec. 3.3, requires of a signature.
	/// In RSASSA-PSS-params, a hash AlgorithmIdentifier may have NULL or absent parameters (RFC 4055, Sec. 2.1), and the trailer field must be 1, absent or present (RFC 4055, Sec. 3.1).
	/// </para>
	/// <para>
	/// The instance does not use the platform, and <see cref="ExportSubjectPublicKeyInfo" /> writes a copy of <paramref name="source" />.
	/// </para>
	/// </remarks>
	/// <param name="source">The SubjectPublicKeyInfo, with nothing after it.</param>
	/// <returns>An instance that holds only the public key.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded SubjectPublicKeyInfo with one of these AlgorithmIdentifiers and an RSAPublicKey (RFC 8017, Appendix A.1.1), or holds an invalid key: its modulus is not positive and odd, or its public exponent is not odd and at least 3.</exception>
	/// <exception cref="NotSupportedException">The modulus has fewer than 512 or more than 16384 bits, the public exponent has more than 33 bits, or the RSASSA-PSS parameters allow none of <see cref="SignatureAlgorithm.RsaPssSha256" />, <see cref="SignatureAlgorithm.RsaPssSha384" /> and <see cref="SignatureAlgorithm.RsaPssSha512" />.</exception>
	public static PlatformRsaKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
	{
		byte[] encoded = source.ToArray();
		SubjectPublicKeyInfo info = SubjectPublicKeyInfo.Decode(encoded, nameof(source));
		SignatureAlgorithm[] algorithms = AllowedBy(info.Algorithm, nameof(source));
		ReadOnlySpan<byte> modulus;
		ReadOnlySpan<byte> exponent;

		// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }, whose INTEGERs are positive.
		try
		{
			DerReader sequence = DerReader.ReadSoleSequence(info.PublicKey);
			modulus = sequence.ReadIntegerBytes().Span;
			exponent = sequence.ReadIntegerBytes().Span;
			sequence.ThrowIfNotEmpty();
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The RSA public key is invalid.", nameof(source), e);
		}

		if (modulus[0] >= 0x80 || exponent[0] >= 0x80)
		{
			throw new ArgumentException("The RSA public key is invalid.", nameof(source));
		}

		RsaPublicKey publicKey = RsaPublicKey.Create(modulus, exponent, nameof(source));
		return new PlatformRsaKey(publicKey, encoded, Supported(algorithms, publicKey));
	}

	/// <inheritdoc />
	public bool Supports(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return Array.IndexOf(_algorithms, algorithm) >= 0;
	}

	/// <inheritdoc />
	public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfUnsupported(algorithm);
		return _publicKey.Length;
	}

	/// <inheritdoc />
	public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfUnsupported(algorithm);

		if (_key is null)
		{
			throw new InvalidOperationException("The instance does not hold the private key.");
		}

		int length = _publicKey.Length;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, length, nameof(destination));

		// The platform writes to a buffer of its own, so that destination stays unchanged if it fails.
		Span<byte> signature = stackalloc byte[length];

		lock (_signLock)
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			PlatformSign(_key, algorithm, message, signature);
		}

		if (!_publicKey.Verify(algorithm, message, signature))
		{
			throw new CryptographicException("The platform made a signature that does not verify.");
		}

		signature.CopyTo(destination);
		return length;
	}

	/// <inheritdoc />
	public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfUnsupported(algorithm);
		return _publicKey.Verify(algorithm, message, signature);
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
	/// Throws <see cref="InvalidOperationException" />: the private key is not exportable, or the instance does not hold it.
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
		// The platform key is not disposed while it signs.
		lock (_signLock)
		{
			if (_disposed)
			{
				return;
			}

			_disposed = true;
		}

		_key?.Dispose();
	}

	private static (RsaPublicKey PublicKey, byte[] SubjectPublicKeyInfo) ExportPublicKey(RSA key)
	{
		ArgumentNullException.ThrowIfNull(key);

		RSAParameters parameters = key.ExportParameters(false);
		RsaPublicKey publicKey = RsaPublicKey.Create(parameters.Modulus, parameters.Exponent, nameof(key));
		AsnWriter rsaPublicKey = new(AsnEncodingRules.DER);

		using (rsaPublicKey.PushSequence())
		{
			rsaPublicKey.WriteInteger(publicKey.Modulus);
			rsaPublicKey.WriteInteger(publicKey.Exponent);
		}

		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteEncodedValue(RsaEncryption);
			writer.WriteBitString(rsaPublicKey.Encode());
		}

		return (publicKey, writer.Encode());
	}

	// The algorithms that the AlgorithmIdentifier of a SubjectPublicKeyInfo allows, whatever the modulus.
	private static SignatureAlgorithm[] AllowedBy(AlgorithmIdentifier algorithm, string parameterName)
	{
		if (algorithm is { Oid: AlgorithmIdentifier.RsaEncryptionOid, Parameters.Span: [0x05, 0x00] })
		{
			return AllAlgorithms;
		}

		if (algorithm.Oid is not AlgorithmIdentifier.RsassaPssOid)
		{
			throw new ArgumentException("The key is not an RSA key with valid parameters.", parameterName);
		}

		if (algorithm.Parameters.IsEmpty)
		{
			return PssAlgorithms;
		}

		bool allowed;
		SignatureAlgorithm pss;

		try
		{
			allowed = AlgorithmIdentifier.TryReadRsassaPssParameters(algorithm.Parameters, out pss, out int hashLength, out int saltLength) && saltLength <= hashLength;
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The RSASSA-PSS parameters of the key are invalid.", parameterName, e);
		}

		return allowed ? [pss] : throw new NotSupportedException("The RSASSA-PSS parameters of the key allow none of the signature algorithms.");
	}

	// Signs once, as the constructor describes: RSASSA-PSS, then RSASSA-PKCS1-v1_5 if it fails or does not fit.
	private static SignatureAlgorithm[] Probe(RSA key, RsaPublicKey publicKey)
	{
		Span<byte> signature = stackalloc byte[publicKey.Length];

		if (publicKey.Fits(SignatureAlgorithm.RsaPssSha256) && TrySign(key, publicKey, SignatureAlgorithm.RsaPssSha256, signature, out _))
		{
			return Supported(AllAlgorithms, publicKey);
		}

		if (!TrySign(key, publicKey, SignatureAlgorithm.RsaPkcs1Sha256, signature, out Exception? error))
		{
			throw new CryptographicException("The key failed to sign with RSASSA-PKCS1-v1_5 and SHA-256.", error);
		}

		return Supported(Pkcs1Algorithms, publicKey);
	}

	// Whether the platform signs the probe message with algorithm, and the signature verifies; error is what the platform threw.
	private static bool TrySign(RSA key, RsaPublicKey publicKey, SignatureAlgorithm algorithm, Span<byte> signature, out Exception? error)
	{
		try
		{
			PlatformSign(key, algorithm, ProbeMessage, signature);
		}
		catch (Exception e) when (e is CryptographicException or NotSupportedException)
		{
			error = e;
			return false;
		}

		error = null;
		return publicKey.Verify(algorithm, ProbeMessage, signature);
	}

	// signature is as long as the modulus.
	private static void PlatformSign(RSA key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> signature)
	{
		(HashAlgorithmName hash, _, RSASignaturePadding padding) = ParametersOf(algorithm);

		if (!key.TrySignData(message, signature, hash, padding, out int written) || written != signature.Length)
		{
			throw new CryptographicException("The platform made a signature that is not as long as the modulus.");
		}
	}

	// The members of AllAlgorithms that algorithms holds and the modulus fits, in that order.
	private static SignatureAlgorithm[] Supported(ReadOnlySpan<SignatureAlgorithm> algorithms, RsaPublicKey publicKey)
	{
		SignatureAlgorithm[] supported = new SignatureAlgorithm[AllAlgorithms.Length];
		int count = 0;

		foreach (SignatureAlgorithm algorithm in AllAlgorithms)
		{
			if (algorithms.Contains(algorithm) && publicKey.Fits(algorithm))
			{
				supported[count++] = algorithm;
			}
		}

		return count == supported.Length ? supported : supported.AsSpan(0, count).ToArray();
	}

	private static (HashAlgorithmName Hash, int HashLength, RSASignaturePadding Padding) ParametersOf(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => (HashAlgorithmName.SHA256, 32, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha384 => (HashAlgorithmName.SHA384, 48, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPkcs1Sha512 => (HashAlgorithmName.SHA512, 64, RSASignaturePadding.Pkcs1),
			SignatureAlgorithm.RsaPssSha256 => (HashAlgorithmName.SHA256, 32, RSASignaturePadding.Pss),
			SignatureAlgorithm.RsaPssSha384 => (HashAlgorithmName.SHA384, 48, RSASignaturePadding.Pss),
			_ => (HashAlgorithmName.SHA512, 64, RSASignaturePadding.Pss)
		};
	}

	private void ThrowIfUnsupported(SignatureAlgorithm algorithm)
	{
		if (Array.IndexOf(_algorithms, algorithm) < 0)
		{
			throw new ArgumentException("The key does not support the signature algorithm.", nameof(algorithm));
		}
	}

	private InvalidOperationException NotExportable()
	{
		return new InvalidOperationException(_key is null ? "The instance does not hold the private key." : "The private key is not exportable.");
	}

	// An RSA public key within the bounds, which verifies without the platform. Instances are immutable.
	private readonly struct RsaPublicKey
	{
		private RsaPublicKey(BigInteger modulus, BigInteger exponent, int modulusBits)
		{
			Modulus = modulus;
			Exponent = exponent;
			ModulusBits = modulusBits;
		}

		public BigInteger Modulus { get; }

		public BigInteger Exponent { get; }

		public int ModulusBits { get; }

		// k, the length of the modulus and of a signature in bytes.
		public int Length => (ModulusBits + 7) / 8;

		// The unsigned big-endian modulus and exponent, which may have leading zeros.
		public static RsaPublicKey Create(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> exponent, string parameterName)
		{
			modulus = TrimLeadingZeros(modulus);
			exponent = TrimLeadingZeros(exponent);

			// RFC 8017, Sec. 3.1: n is a product of odd primes, and e is odd, since it is coprime to λ(n), and at least 3.
			if (modulus.IsEmpty || (modulus[^1] & 1) is 0 || exponent.IsEmpty || (exponent[^1] & 1) is 0 || exponent is [1])
			{
				throw new ArgumentException("The RSA public key is invalid.", parameterName);
			}

			// The lengths in bytes come first, so that the bit lengths of longer values are never computed.
			int modulusBits = modulus.Length <= (MaxModulusBits + 7) / 8 ? GetBitLength(modulus) : int.MaxValue;

			if (modulusBits is < MinModulusBits or > MaxModulusBits || exponent.Length > (MaxPublicExponentBits + 7) / 8 || GetBitLength(exponent) > MaxPublicExponentBits)
			{
				throw new NotSupportedException("The RSA modulus must have 512 to 16384 bits, and the public exponent at most 33 bits.");
			}

			return new RsaPublicKey(new BigInteger(modulus, isUnsigned: true, isBigEndian: true), new BigInteger(exponent, isUnsigned: true, isBigEndian: true), modulusBits);
		}

		// RFC 8017: EMSA-PSS needs emLen = ⌈(modBits − 1)/8⌉ ≥ hLen + sLen + 2 (Sec. 9.1.1, step 3), and EMSA-PKCS1-v1_5 needs k ≥ tLen + 11, where the DigestInfo T has 19 bytes before the hash (Sec. 9.2, step 3).
		public bool Fits(SignatureAlgorithm algorithm)
		{
			(_, int hashLength, RSASignaturePadding padding) = ParametersOf(algorithm);
			return padding == RSASignaturePadding.Pss ? (ModulusBits + 6) / 8 >= 2 * hashLength + 2 : Length >= 19 + hashLength + 11;
		}

		// RSASSA-PSS-VERIFY (RFC 8017, Sec. 8.1.2) or RSASSA-PKCS1-V1_5-VERIFY (Sec. 8.2.2) with an algorithm that fits.
		public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
		{
			// Step 1.
			if (signature.Length != Length)
			{
				return false;
			}

			// Step 2: RSAVP1 (Sec. 5.2.2) on the signature representative, which must be below the modulus. The exponent bounds the work.
			BigInteger representative = new(signature, isUnsigned: true, isBigEndian: true);

			if (representative >= Modulus)
			{
				return false;
			}

			BigInteger messageRepresentative = BigInteger.ModPow(representative, Exponent, Modulus);
			(HashAlgorithmName hash, int hashLength, RSASignaturePadding padding) = ParametersOf(algorithm);
			bool pss = padding == RSASignaturePadding.Pss;

			// I2OSP (Sec. 4.1) into emLen = ⌈(modBits − 1)/8⌉ bytes for RSASSA-PSS, which may be one byte short of k, and into k bytes for RSASSA-PKCS1-v1_5.
			Span<byte> encoded = stackalloc byte[pss ? (ModulusBits + 6) / 8 : Length];
			int byteCount = messageRepresentative.GetByteCount(isUnsigned: true);

			if (byteCount > encoded.Length)
			{
				return false;
			}

			encoded.Clear();
			messageRepresentative.TryWriteBytes(encoded.Slice(encoded.Length - byteCount), out _, isUnsigned: true, isBigEndian: true);

			Span<byte> digest = stackalloc byte[hashLength];
			CryptographicOperations.HashData(hash, message, digest);

			return pss ? IsPssEncoding(encoded, hash, digest) : IsPkcs1Encoding(encoded, algorithm, digest);
		}

		// EM = 0x00 || 0x01 || PS || 0x00 || T (RFC 8017, Sec. 9.2), compared with the encoded message byte for byte for each DigestInfo: the lengths of PS and T follow from k and the hash, so nothing is parsed.
		private static bool IsPkcs1Encoding(ReadOnlySpan<byte> encoded, SignatureAlgorithm algorithm, ReadOnlySpan<byte> digest)
		{
			return algorithm switch
			{
				SignatureAlgorithm.RsaPkcs1Sha256 => IsPkcs1Encoding(encoded, Sha256DigestInfo, digest) || IsPkcs1Encoding(encoded, Sha256DigestInfoWithoutParameters, digest),
				SignatureAlgorithm.RsaPkcs1Sha384 => IsPkcs1Encoding(encoded, Sha384DigestInfo, digest) || IsPkcs1Encoding(encoded, Sha384DigestInfoWithoutParameters, digest),
				_ => IsPkcs1Encoding(encoded, Sha512DigestInfo, digest) || IsPkcs1Encoding(encoded, Sha512DigestInfoWithoutParameters, digest)
			};
		}

		private static bool IsPkcs1Encoding(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> digestInfo, ReadOnlySpan<byte> digest)
		{
			int separator = encoded.Length - digestInfo.Length - digest.Length - 1;

			return encoded[0] is 0x00
				&& encoded[1] is 0x01
				&& !encoded.Slice(2, separator - 2).ContainsAnyExcept((byte)0xFF)
				&& encoded[separator] is 0x00
				&& encoded.Slice(separator + 1, digestInfo.Length).SequenceEqual(digestInfo)
				&& encoded.Slice(encoded.Length - digest.Length).SequenceEqual(digest);
		}

		// EMSA-PSS-VERIFY (RFC 8017, Sec. 9.1.2) with emBits = modBits − 1, MGF1 with the hash, and sLen = hLen; Fits passed step 3. encoded is changed.
		private bool IsPssEncoding(Span<byte> encoded, HashAlgorithmName hash, ReadOnlySpan<byte> digest)
		{
			int hashLength = digest.Length;
			int zeroBits = 8 * encoded.Length - (ModulusBits - 1);

			// Step 4.
			if (encoded[^1] is not 0xBC)
			{
				return false;
			}

			// Steps 5 and 6.
			Span<byte> db = encoded.Slice(0, encoded.Length - hashLength - 1);
			ReadOnlySpan<byte> h = encoded.Slice(db.Length, hashLength);

			if (db[0] >> 8 - zeroBits is not 0)
			{
				return false;
			}

			// Steps 7 to 9.
			Mgf1Xor(hash, h, db);
			db[0] &= (byte)(0xFF >> zeroBits);

			// Step 10: PS, emLen − hLen − sLen − 2 zero bytes, then 0x01.
			int paddingLength = db.Length - hashLength - 1;

			if (db.Slice(0, paddingLength).ContainsAnyExcept((byte)0) || db[paddingLength] is not 0x01)
			{
				return false;
			}

			// Steps 11 to 14: H' = Hash(0x00 × 8 || mHash || salt).
			Span<byte> prefixed = stackalloc byte[8 + 2 * hashLength];
			prefixed.Slice(0, 8).Clear();
			digest.CopyTo(prefixed.Slice(8));
			db.Slice(db.Length - hashLength).CopyTo(prefixed.Slice(8 + hashLength));

			Span<byte> expected = stackalloc byte[hashLength];
			CryptographicOperations.HashData(hash, prefixed, expected);
			return h.SequenceEqual(expected);
		}

		// destination ^= MGF1(seed, destination.Length) (RFC 8017, Appendix B.2.1), with a hash as long as seed.
		private static void Mgf1Xor(HashAlgorithmName hash, ReadOnlySpan<byte> seed, Span<byte> destination)
		{
			Span<byte> input = stackalloc byte[MaxHashLength + 4].Slice(0, seed.Length + 4);
			Span<byte> mask = stackalloc byte[MaxHashLength].Slice(0, seed.Length);
			seed.CopyTo(input);

			for (uint counter = 0; !destination.IsEmpty; ++counter)
			{
				BinaryPrimitives.WriteUInt32BigEndian(input.Slice(seed.Length), counter);
				CryptographicOperations.HashData(hash, input, mask);

				// Both slices have the length that bounds the loop, so that it indexes them without bounds checks.
				int length = Math.Min(mask.Length, destination.Length);
				Span<byte> block = destination.Slice(0, length);
				ReadOnlySpan<byte> blockMask = mask.Slice(0, length);

				for (int i = 0; i < block.Length; ++i)
				{
					block[i] ^= blockMask[i];
				}

				destination = destination.Slice(length);
			}
		}

		private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
		{
			int start = value.IndexOfAnyExcept((byte)0);
			return start < 0 ? default : value.Slice(start);
		}

		// Of a value without leading zeros.
		private static int GetBitLength(ReadOnlySpan<byte> value)
		{
			return 8 * value.Length - BitOperations.LeadingZeroCount(value[0]) + 24;
		}
	}
}
