using CryptoBase.Internal;

namespace CryptoBase.X509;

/// <summary>
/// Represents a SubjectPublicKeyInfo (RFC 5280, Sec. 4.1.2.7): the algorithm of a public key and the key.
/// </summary>
/// <remarks>Decoding checks the structure, not the key; <see cref="ISignatureKey{TSelf}.ImportSubjectPublicKeyInfo" /> of a key type imports the key from <see cref="Encoded" />.</remarks>
public sealed class SubjectPublicKeyInfo
{
	internal const string ECPublicKeyOid = "1.2.840.10045.2.1";

	private SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> encoded)
	{
		Algorithm = algorithm;
		PublicKey = publicKey;
		Encoded = encoded;
		KeyAlgorithm = GetKeyAlgorithm(algorithm);
	}

	/// <summary>
	/// Gets the algorithm of the key.
	/// </summary>
	public AlgorithmIdentifier Algorithm { get; }

	/// <summary>
	/// Gets the subjectPublicKey, the bytes of its BIT STRING.
	/// </summary>
	public ReadOnlyMemory<byte> PublicKey { get; }

	/// <summary>
	/// Gets the DER encoding of the whole SubjectPublicKeyInfo.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the type of the key, by the algorithm and, for an EC key, its named curve.
	/// </summary>
	/// <remarks>
	/// <para>
	/// A type is given only with the parameters that the importers of the package accept, <c>SignatureKey.ImportSubjectPublicKeyInfo</c> of CryptoBase and, for RSA, <see cref="PlatformRsaKey.ImportSubjectPublicKeyInfo" />.
	/// rsaEncryption gives <see cref="PublicKeyAlgorithm.Rsa" /> with NULL parameters (RFC 4055, Sec. 1.2).
	/// id-RSASSA-PSS gives <see cref="PublicKeyAlgorithm.RsaPss" /> without parameters, which allow RSASSA-PSS with each hash, or with DER-encoded RSASSA-PSS-params (RFC 4055, Sec. 3.1) that allow <see cref="SignatureAlgorithm.RsaPssSha256" />, <see cref="SignatureAlgorithm.RsaPssSha384" /> or <see cref="SignatureAlgorithm.RsaPssSha512" />:
	/// SHA-256, SHA-384 or SHA-512 as the hash and the MGF1 hash alike, each hash AlgorithmIdentifier with NULL or absent parameters (Sec. 2.1), a saltLength from 0 to the length of the hash (Sec. 3.3), and the trailer field 1.
	/// id-ecPublicKey gives <see cref="PublicKeyAlgorithm.EcdsaP256" />, <see cref="PublicKeyAlgorithm.EcdsaP384" /> or <see cref="PublicKeyAlgorithm.EcdsaP521" /> with the namedCurve of P-256, P-384 or P-521 as its parameters (RFC 5480, Sec. 2.1.1.1), and <see cref="PublicKeyAlgorithm.SM2" /> with that of SM2, 1.2.156.10197.1.301.
	/// id-Ed25519 and id-Ed448 (RFC 8410, Sec. 3), and id-ml-dsa-44, id-ml-dsa-65 and id-ml-dsa-87 (RFC 9881), give their types without parameters.
	/// </para>
	/// <para>
	/// Any other AlgorithmIdentifier gives <see cref="PublicKeyAlgorithm.Unknown" />: another algorithm, such as DSA or X25519, another curve, explicit curve parameters, or one of these algorithms with other parameters.
	/// The property reads the AlgorithmIdentifier alone, not <see cref="PublicKey" />, so an importer may still refuse a key of a known type for the key itself, such as an RSA modulus that it does not support or a point that is not on the curve.
	/// It never throws.
	/// </para>
	/// </remarks>
	public PublicKeyAlgorithm KeyAlgorithm { get; }

	// The namedCurve parameters of id-ecPublicKey for P-256, P-384 and P-521 (RFC 5480, Sec. 2.1.1.1), and for SM2, 1.2.156.10197.1.301 (GB/T 35275-2017).
	private static ReadOnlySpan<byte> P256 => [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

	private static ReadOnlySpan<byte> P384 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

	private static ReadOnlySpan<byte> P521 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

	private static ReadOnlySpan<byte> SM2 => [0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D];

	/// <summary>
	/// Decodes a DER-encoded SubjectPublicKeyInfo.
	/// </summary>
	/// <param name="source">The SubjectPublicKeyInfo, with nothing after it.</param>
	/// <returns>The decoded SubjectPublicKeyInfo, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded SubjectPublicKeyInfo whose subjectPublicKey is a whole number of bytes.</exception>
	public static SubjectPublicKeyInfo Decode(ReadOnlySpan<byte> source)
	{
		return Decode(source.ToArray(), nameof(source));
	}

	/// <summary>
	/// Gets the length of the modulus of an RSA key, in bits.
	/// </summary>
	/// <remarks>
	/// The length is that of the modulus without leading zeros.
	/// A length beyond <see cref="int.MaxValue" />, of a modulus of more than 256 MiB, is <see cref="int.MaxValue" />.
	/// The public exponent is not checked; <see cref="CertificateAlgorithmPolicy.IsWithinVerificationBounds" /> checks the whole key.
	/// </remarks>
	/// <returns>The length, or <see langword="null" /> if <see cref="KeyAlgorithm" /> is neither <see cref="PublicKeyAlgorithm.Rsa" /> nor <see cref="PublicKeyAlgorithm.RsaPss" />.</returns>
	/// <exception cref="CryptographicException"><see cref="PublicKey" /> is not a DER-encoded RSAPublicKey (RFC 8017, Appendix A.1.1), or its modulus is not positive.</exception>
	public int? GetRsaKeySize()
	{
		if (KeyAlgorithm is not (PublicKeyAlgorithm.Rsa or PublicKeyAlgorithm.RsaPss))
		{
			return null;
		}

		ReadOnlySpan<byte> modulus;

		try
		{
			modulus = ReadRsaPublicKey(out _);
		}
		catch (AsnContentException e)
		{
			throw new CryptographicException("The RSA public key is invalid.", e);
		}

		return CertificateAlgorithmPolicy.IsPositive(modulus) ? CertificateAlgorithmPolicy.GetBitLength(modulus) : throw new CryptographicException("The modulus of the RSA public key is not positive.");
	}

	// encoded is owned by the new instance.
	internal static SubjectPublicKeyInfo Decode(byte[] encoded, string parameterName)
	{
		try
		{
			DerReader reader = new(encoded);
			SubjectPublicKeyInfo info = Read(ref reader);
			reader.ThrowIfNotEmpty();
			return info;
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The SubjectPublicKeyInfo is invalid.", parameterName, e);
		}
	}

	// SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }; the results are slices of the reader's memory.
	internal static SubjectPublicKeyInfo Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence(out ReadOnlyMemory<byte> encoded);
		AlgorithmIdentifier algorithm = AlgorithmIdentifier.Read(ref contents);
		ReadOnlyMemory<byte> publicKey = contents.ReadBitString();
		contents.ThrowIfNotEmpty();
		return new SubjectPublicKeyInfo(algorithm, publicKey, encoded);
	}

	// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 8017, Appendix A.1.1), read from the subjectPublicKey whatever the algorithm:
	// the contents of the modulus, and of the public exponent in exponent.
	// Throws AsnContentException if it does not decode.
	internal ReadOnlySpan<byte> ReadRsaPublicKey(out ReadOnlySpan<byte> exponent)
	{
		DerReader sequence = DerReader.ReadSoleSequence(PublicKey);
		ReadOnlySpan<byte> modulus = sequence.ReadIntegerBytes().Span;
		exponent = sequence.ReadIntegerBytes().Span;
		sequence.ThrowIfNotEmpty();
		return modulus;
	}

	// The type of a key by its AlgorithmIdentifier, as KeyAlgorithm describes.
	private static PublicKeyAlgorithm GetKeyAlgorithm(AlgorithmIdentifier algorithm)
	{
		ReadOnlySpan<byte> parameters = algorithm.Parameters.Span;

		return algorithm.Oid switch
		{
			AlgorithmIdentifier.RsaEncryptionOid when parameters is [0x05, 0x00] => PublicKeyAlgorithm.Rsa,
			AlgorithmIdentifier.RsassaPssOid when AllowsRsassaPss(parameters) => PublicKeyAlgorithm.RsaPss,
			ECPublicKeyOid when parameters.SequenceEqual(P256) => PublicKeyAlgorithm.EcdsaP256,
			ECPublicKeyOid when parameters.SequenceEqual(P384) => PublicKeyAlgorithm.EcdsaP384,
			ECPublicKeyOid when parameters.SequenceEqual(P521) => PublicKeyAlgorithm.EcdsaP521,
			ECPublicKeyOid when parameters.SequenceEqual(SM2) => PublicKeyAlgorithm.SM2,
			"1.3.101.112" when parameters.IsEmpty => PublicKeyAlgorithm.Ed25519,
			"1.3.101.113" when parameters.IsEmpty => PublicKeyAlgorithm.Ed448,
			"2.16.840.1.101.3.4.3.17" when parameters.IsEmpty => PublicKeyAlgorithm.MLDsa44,
			"2.16.840.1.101.3.4.3.18" when parameters.IsEmpty => PublicKeyAlgorithm.MLDsa65,
			"2.16.840.1.101.3.4.3.19" when parameters.IsEmpty => PublicKeyAlgorithm.MLDsa87,
			_ => PublicKeyAlgorithm.Unknown
		};
	}

	// Whether the parameters of an id-RSASSA-PSS key allow a signature algorithm, as the importers require: absent, or RSASSA-PSS-params that name one, with a saltLength no longer than the hash.
	private static bool AllowsRsassaPss(ReadOnlySpan<byte> parameters)
	{
		if (parameters.IsEmpty)
		{
			return true;
		}

		try
		{
			return RsassaPssParameters.TryRead(parameters, out _, out int hashLength, out int saltLength) && saltLength <= hashLength;
		}
		catch (AsnContentException)
		{
			return false;
		}
	}
}
