using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase.X509;

/// <summary>
/// Provides the policy on the algorithms and keys of certificates that <see cref="TrustAnchorCertificateValidator" /> applies, for a caller that checks certificates itself, such as one that validates them with another validator.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IsWithinVerificationBounds" /> bounds the work of verifying with a key, and is meant for every certificate that a peer sends, before any validator runs.
/// <see cref="GetSignatureStrength" /> classifies the signature algorithm of each certificate whose signature a path relies on, and <see cref="IsAcceptableInPath" /> each key that a path relies on.
/// </para>
/// <para>
/// <see cref="TrustAnchorCertificateValidator" /> applies the last two to every certificate of a path but the signature of the trust anchor:
/// a signature that is <see cref="CertificateSignatureStrength.Forbidden" /> or <see cref="CertificateSignatureStrength.Weak" /> gives <see cref="CertificateValidationError.WeakAlgorithm" />, and one that is <see cref="CertificateSignatureStrength.Unsupported" /> gives <see cref="CertificateValidationError.UnsupportedAlgorithm" />.
/// </para>
/// </remarks>
public static class CertificateAlgorithmPolicy
{
	// The default fewest bits of an RSA modulus (RFC 9325, Sec. 4.5), and the fewest that a caller may set.
	internal const int DefaultMinRsaKeySize = 2048;
	internal const int MinRsaKeySizeAllowed = 1024;

	// The bounds on the work of a verification, those of PlatformRsaKey.
	internal const int MaxRsaKeySize = 16384;
	private const int MaxRsaPublicExponentSize = 33;

	private const string DsaOid = "1.2.840.10040.4.1";
	private const string Sha1Oid = "1.3.14.3.2.26";
	private const string EcdsaWithSpecifiedOid = "1.2.840.10045.4.3";

	private static readonly Asn1Tag HashAlgorithmTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag MaskGenAlgorithmTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag SaltLengthTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag TrailerFieldTag = new(TagClass.ContextSpecific, 3, true);

	/// <summary>
	/// Classifies the algorithm of a certificate's signature: whether the package verifies it, and otherwise how weak it is.
	/// </summary>
	/// <remarks>
	/// The algorithms that <see cref="AlgorithmIdentifier.TryGetSignatureAlgorithm" /> names are <see cref="CertificateSignatureStrength.Acceptable" />.
	/// Of the others, those with MD2, MD4, MD5 or SHA-0, the SHA that SHA-1 replaced, are <see cref="CertificateSignatureStrength.Forbidden" />:
	/// md2WithRSAEncryption, md4WithRSAEncryption and md5WithRSAEncryption;
	/// the OIW's md4WithRSA, md5WithRSA, md4WithRSAEncryption, md2WithRSASignature and md5WithRSASignature, 1.3.14.3.2.2, 1.3.14.3.2.3, 1.3.14.3.2.4, 1.3.14.3.2.24 and 1.3.14.3.2.25, and the md2RSA of its directory arc, 1.3.14.7.2.3.1;
	/// the OIW's dsaWithSHA, shaWithRSASignature and dsaCommonWithSHA, with SHA-0, 1.3.14.3.2.13, 1.3.14.3.2.15 and 1.3.14.3.2.21;
	/// id-RSASSA-PSS whose hash or MGF1 hash is MD2, MD4, MD5 or SHA-0;
	/// and ecdsa-with-Specified, 1.2.840.10045.4.3 of ANSI X9.62, whose parameters, the AlgorithmIdentifier of its hash, name MD2, MD4, MD5 or SHA-0.
	/// Those with SHA-1 or SHA-224, and DSA with any other hash, are <see cref="CertificateSignatureStrength.Weak" />:
	/// sha1WithRSAEncryption, sha224WithRSAEncryption, ecdsa-with-SHA1 and ecdsa-with-SHA224;
	/// the OIW's sha-1WithRSAEncryption, 1.3.14.3.2.29;
	/// dsa-with-sha1, the OIW's dsaWithSHA1 and dsaWithCommonSHA1, and NIST's DSA with SHA-2 (RFC 5758, Sec. 3.1) and SHA-3, 2.16.840.1.101.3.4.3.1 to 2.16.840.1.101.3.4.3.8;
	/// id-RSASSA-PSS whose hash or MGF1 hash is SHA-1 or SHA-224, as they are without parameters (RFC 4055, Sec. 3.1);
	/// and ecdsa-with-Specified whose parameters name SHA-1 or SHA-224.
	/// Parameters that do not decode are <see cref="CertificateSignatureStrength.Forbidden" />:
	/// those of id-RSASSA-PSS that are present but are not DER-encoded RSASSA-PSS-params, with its fields in order and nothing else;
	/// and those of ecdsa-with-Specified that are absent or are not a DER-encoded AlgorithmIdentifier, an OBJECT IDENTIFIER and at most one value in a SEQUENCE, with nothing else.
	/// Where more than one of these holds, as for RSASSA-PSS with MD5 and MGF1 with SHA-1, the most severe one stands.
	/// Any other algorithm is <see cref="CertificateSignatureStrength.Unsupported" />, RSASSA-PSS with SHA-256 but another saltLength and ecdsa-with-Specified with SHA-256 among them.
	/// </remarks>
	/// <param name="signatureAlgorithm">The signature algorithm of a certificate, <see cref="Certificate.SignatureAlgorithm" />.</param>
	/// <returns>The classification.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="signatureAlgorithm" /> is <see langword="null" />.</exception>
	public static CertificateSignatureStrength GetSignatureStrength(AlgorithmIdentifier signatureAlgorithm)
	{
		ArgumentNullException.ThrowIfNull(signatureAlgorithm);

		if (signatureAlgorithm.TryGetSignatureAlgorithm(out _))
		{
			return CertificateSignatureStrength.Acceptable;
		}

		return signatureAlgorithm.Oid switch
		{
			// md2WithRSAEncryption, md4WithRSAEncryption and md5WithRSAEncryption.
			"1.2.840.113549.1.1.2" or "1.2.840.113549.1.1.3" or "1.2.840.113549.1.1.4" => CertificateSignatureStrength.Forbidden,
			// The OIW's md4WithRSA, md5WithRSA, md4WithRSAEncryption, md2WithRSASignature and md5WithRSASignature, and the md2RSA of its directory arc, which Windows also knows.
			"1.3.14.3.2.2" or "1.3.14.3.2.3" or "1.3.14.3.2.4" or "1.3.14.3.2.24" or "1.3.14.3.2.25" or "1.3.14.7.2.3.1" => CertificateSignatureStrength.Forbidden,
			// The OIW's dsaWithSHA, shaWithRSASignature and dsaCommonWithSHA, whose SHA is SHA-0.
			"1.3.14.3.2.13" or "1.3.14.3.2.15" or "1.3.14.3.2.21" => CertificateSignatureStrength.Forbidden,
			// sha1WithRSAEncryption and sha224WithRSAEncryption, and the OIW's sha-1WithRSAEncryption.
			"1.2.840.113549.1.1.5" or "1.2.840.113549.1.1.14" or "1.3.14.3.2.29" => CertificateSignatureStrength.Weak,
			// ecdsa-with-SHA1 and ecdsa-with-SHA224.
			"1.2.840.10045.4.1" or "1.2.840.10045.4.3.1" => CertificateSignatureStrength.Weak,
			// dsa-with-sha1, the OIW's dsaWithSHA1 and dsaWithCommonSHA1, and NIST's DSA with SHA-2 (RFC 5758, Sec. 3.1) and SHA-3.
			"1.2.840.10040.4.3" or "1.3.14.3.2.27" or "1.3.14.3.2.28" => CertificateSignatureStrength.Weak,
			"2.16.840.1.101.3.4.3.1" or "2.16.840.1.101.3.4.3.2" or "2.16.840.1.101.3.4.3.3" or "2.16.840.1.101.3.4.3.4" => CertificateSignatureStrength.Weak,
			"2.16.840.1.101.3.4.3.5" or "2.16.840.1.101.3.4.3.6" or "2.16.840.1.101.3.4.3.7" or "2.16.840.1.101.3.4.3.8" => CertificateSignatureStrength.Weak,
			AlgorithmIdentifier.RsassaPssOid => GetRsassaPssStrength(signatureAlgorithm.Parameters),
			EcdsaWithSpecifiedOid => GetEcdsaWithSpecifiedStrength(signatureAlgorithm.Parameters),
			_ => CertificateSignatureStrength.Unsupported
		};
	}

	/// <summary>
	/// Determines whether verifying with a key takes bounded work: whether an RSA key is valid, with a modulus and a public exponent that are not too long.
	/// </summary>
	/// <remarks>
	/// A key whose algorithm is rsaEncryption or id-RSASSA-PSS, whatever its parameters, must be a DER-encoded RSAPublicKey (RFC 8017, Appendix A.1.1) whose integers are positive;
	/// its modulus must be odd and have at most 16384 bits, and its public exponent must be odd, other than 1, and have at most 33 bits.
	/// Those are the bounds of <see cref="PlatformRsaKey" />; <see cref="IsAcceptableInPath" /> also requires them.
	/// The verification of any other key takes work that its algorithm bounds, so the method returns <see langword="true" /> for it.
	/// </remarks>
	/// <param name="key">The key, such as <see cref="Certificate.PublicKeyInfo" />.</param>
	/// <returns><see langword="true" /> if the key is not RSA, or is an RSA key within the bounds; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	public static bool IsWithinVerificationBounds(SubjectPublicKeyInfo key)
	{
		ArgumentNullException.ThrowIfNull(key);

		if (!IsRsa(key.Algorithm))
		{
			return true;
		}

		return ReadRsaPublicKey(key, out int modulusBits, out int exponentBits, out _) is null && modulusBits <= MaxRsaKeySize && exponentBits <= MaxRsaPublicExponentSize;
	}

	/// <summary>
	/// Determines whether a key is strong enough for a certification path, as <see cref="TrustAnchorCertificateValidator" /> requires of each key in one.
	/// </summary>
	/// <remarks>
	/// A key whose algorithm is rsaEncryption or id-RSASSA-PSS, whatever its parameters, must be within the bounds of <see cref="IsWithinVerificationBounds" />, and its modulus must have at least <paramref name="minRsaKeySize" /> bits and a multiple of 8, as the CA/Browser Forum Baseline Requirements, Sec. 6.1.5, require.
	/// An EC key, id-ecPublicKey, must be on the named curve P-256, P-384, P-521 or that of SM2, as <see cref="SubjectPublicKeyInfo.KeyAlgorithm" /> gives them; explicit curve parameters, which RFC 5480, Sec. 2.1.1, forbids, are refused.
	/// A DSA key is refused.
	/// Any other key is accepted: whether it can be imported and verify is for the importer and the verifier to decide.
	/// </remarks>
	/// <param name="key">The key, such as <see cref="Certificate.PublicKeyInfo" />.</param>
	/// <param name="minRsaKeySize">The fewest bits of an RSA modulus, from 1024 to 16384, as for <see cref="TrustAnchorCertificateValidator.MinRsaKeySize" />; 2048 by default (RFC 9325, Sec. 4.5).</param>
	/// <returns><see langword="true" /> if the policy accepts the key; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="key" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="minRsaKeySize" /> is less than 1024 or greater than 16384.</exception>
	public static bool IsAcceptableInPath(SubjectPublicKeyInfo key, int minRsaKeySize = DefaultMinRsaKeySize)
	{
		ArgumentNullException.ThrowIfNull(key);
		ThrowIfMinRsaKeySizeOutOfRange(minRsaKeySize);
		return CheckPublicKey(key, minRsaKeySize, out _) is null;
	}

	// The rule of IsAcceptableInPath and TrustAnchorCertificateValidator.MinRsaKeySize.
	internal static void ThrowIfMinRsaKeySizeOutOfRange(int value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(value, MinRsaKeySizeAllowed, paramName);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(value, MaxRsaKeySize, paramName);
	}

	// Whether a certificate's signature can be verified, as GetSignatureStrength classifies it: null if it is Acceptable, WeakAlgorithm if it is Forbidden or Weak, and UnsupportedAlgorithm otherwise.
	internal static CertificateValidationError? CheckSignatureAlgorithm(AlgorithmIdentifier identifier)
	{
		return GetSignatureStrength(identifier) switch
		{
			CertificateSignatureStrength.Acceptable => null,
			CertificateSignatureStrength.Unsupported => CertificateValidationError.UnsupportedAlgorithm,
			_ => CertificateValidationError.WeakAlgorithm
		};
	}

	// Whether the policy accepts a public key, before it is imported, as IsAcceptableInPath describes: null if so or if the importer decides, and otherwise the error, with its description in reason.
	// An RSA key that does not decode or is invalid is Malformed, and one outside the bounds WeakAlgorithm; an EC key without a named curve is UnsupportedAlgorithm.
	internal static CertificateValidationError? CheckPublicKey(SubjectPublicKeyInfo info, int minRsaKeySize, out string? reason)
	{
		switch (info.Algorithm.Oid)
		{
			case AlgorithmIdentifier.RsaEncryptionOid or AlgorithmIdentifier.RsassaPssOid:
			{
				return CheckRsaPublicKey(info, minRsaKeySize, out reason);
			}
			case SubjectPublicKeyInfo.ECPublicKeyOid:
			{
				if (info.KeyAlgorithm is PublicKeyAlgorithm.EcdsaP256 or PublicKeyAlgorithm.EcdsaP384 or PublicKeyAlgorithm.EcdsaP521 or PublicKeyAlgorithm.SM2)
				{
					break;
				}

				// A namedCurve other than these; specifiedCurve and implicitCurve, which RFC 5480 forbids, are not supported.
				if (info.Algorithm.Parameters.Span is [0x06, ..])
				{
					reason = "has an EC key on a curve other than P-256, P-384, P-521 and that of SM2";
					return CertificateValidationError.WeakAlgorithm;
				}

				reason = "has an EC key without a named curve";
				return CertificateValidationError.UnsupportedAlgorithm;
			}
			case DsaOid:
			{
				reason = "has a DSA key";
				return CertificateValidationError.WeakAlgorithm;
			}
		}

		reason = null;
		return null;
	}

	// Whether an algorithm identifier of a key is RSA, which PlatformRsaKey imports when the caller's importer does not.
	internal static bool IsRsa(AlgorithmIdentifier identifier)
	{
		return identifier.Oid is AlgorithmIdentifier.RsaEncryptionOid or AlgorithmIdentifier.RsassaPssOid;
	}

	// Whether a DER INTEGER, by its contents, is positive: a negative one starts with a set high bit, and zero is one zero byte.
	internal static bool IsPositive(ReadOnlySpan<byte> integer)
	{
		return integer is not ([>= 0x80, ..] or [0x00]);
	}

	// The bit length of a positive DER INTEGER, by its contents, to which DER prefixes a zero byte when the high bit is set.
	// A length beyond int.MaxValue, of an integer of more than 256 MiB, is int.MaxValue, which every bound refuses.
	internal static int GetBitLength(ReadOnlySpan<byte> integer)
	{
		ReadOnlySpan<byte> value = integer is [0x00, _, ..] ? integer.Slice(1) : integer;
		long bits = 8L * value.Length - BitOperations.LeadingZeroCount(value[0]) + 24;
		return bits > int.MaxValue ? int.MaxValue : (int)bits;
	}

	// The RSA key against the bounds of IsWithinVerificationBounds and the policy of IsAcceptableInPath, in that order.
	private static CertificateValidationError? CheckRsaPublicKey(SubjectPublicKeyInfo info, int minRsaKeySize, out string? reason)
	{
		if (ReadRsaPublicKey(info, out int modulusBits, out int exponentBits, out reason) is { } error)
		{
			return error;
		}

		if (modulusBits < minRsaKeySize || modulusBits > MaxRsaKeySize || modulusBits % 8 is not 0)
		{
			reason = $"has an RSA key of {modulusBits} bits; the policy requires a multiple of 8 from {minRsaKeySize} to {MaxRsaKeySize}";
			return CertificateValidationError.WeakAlgorithm;
		}

		if (exponentBits > MaxRsaPublicExponentSize)
		{
			reason = $"has an RSA key whose public exponent has more than {MaxRsaPublicExponentSize} bits";
			return CertificateValidationError.WeakAlgorithm;
		}

		return null;
	}

	// The RSAPublicKey of a key whose algorithm is RSA, with the bit lengths of its modulus and public exponent: null if it is valid, and Malformed, with its description in reason, if not.
	// An odd modulus and an odd exponent of at least 3 (RFC 8017, Sec. 3.1), both positive, make a valid key.
	private static CertificateValidationError? ReadRsaPublicKey(SubjectPublicKeyInfo info, out int modulusBits, out int exponentBits, out string? reason)
	{
		ReadOnlySpan<byte> modulus;
		ReadOnlySpan<byte> exponent;
		(modulusBits, exponentBits) = (0, 0);

		try
		{
			modulus = info.ReadRsaPublicKey(out exponent);
		}
		catch (AsnContentException)
		{
			reason = "has an RSA key that does not decode";
			return CertificateValidationError.Malformed;
		}

		if (!IsPositive(modulus) || !IsPositive(exponent) || (modulus[^1] & 1) is 0 || (exponent[^1] & 1) is 0 || exponent is [1])
		{
			reason = "has an RSA key whose modulus or public exponent is invalid";
			return CertificateValidationError.Malformed;
		}

		(modulusBits, exponentBits) = (GetBitLength(modulus), GetBitLength(exponent));
		reason = null;
		return null;
	}

	// The strength of RSASSA-PSS-params (RFC 4055, Sec. 3.1), whose hash and MGF1 hash default to SHA-1: the most severe of the two hashes.
	// Absent parameters mean SHA-1 for both, which is Weak.
	// Present parameters that are not RSASSA-PSS-params, with each field in order under its tag and nothing else, are Forbidden, as a reader that is less strict could find MD5 in them.
	// The values of saltLength and trailerField are not checked here: with parameters that matched no SignatureAlgorithm, they leave the algorithm Unsupported.
	// A mask generation function other than MGF1 names no hash.
	private static CertificateSignatureStrength GetRsassaPssStrength(ReadOnlyMemory<byte> parameters)
	{
		if (parameters.IsEmpty)
		{
			return CertificateSignatureStrength.Weak;
		}

		try
		{
			DerReader fields = DerReader.ReadSoleSequence(parameters);
			string hash = Sha1Oid;
			string maskHash = hash;

			if (fields.TryReadExplicit(HashAlgorithmTag, out DerReader field))
			{
				hash = ReadAlgorithmIdentifier(field, out _);
			}

			if (fields.TryReadExplicit(MaskGenAlgorithmTag, out field))
			{
				maskHash = ReadAlgorithmIdentifier(field, out DerReader maskParameters) is AlgorithmIdentifier.Mgf1Oid ? ReadAlgorithmIdentifier(maskParameters, out _) : "";
			}

			if (fields.TryReadExplicit(SaltLengthTag, out field))
			{
				_ = field.ReadIntegerBytes();
			}

			if (fields.TryReadExplicit(TrailerFieldTag, out field))
			{
				_ = field.ReadIntegerBytes();
			}

			fields.ThrowIfNotEmpty();
			CertificateSignatureStrength hashStrength = GetHashStrength(hash);
			CertificateSignatureStrength maskHashStrength = GetHashStrength(maskHash);
			return hashStrength > maskHashStrength ? hashStrength : maskHashStrength;
		}
		catch (AsnContentException)
		{
			return CertificateSignatureStrength.Forbidden;
		}
	}

	// ecdsa-with-Specified (ANSI X9.62), whose parameters are the AlgorithmIdentifier of its hash: the strength of that hash.
	// Parameters that are absent or are not an AlgorithmIdentifier alone name no hash that the signature is known to use, so a reader that is less strict could find MD5 in them; they are Forbidden.
	private static CertificateSignatureStrength GetEcdsaWithSpecifiedStrength(ReadOnlyMemory<byte> parameters)
	{
		try
		{
			return GetHashStrength(ReadAlgorithmIdentifier(new DerReader(parameters), out _));
		}
		catch (AsnContentException)
		{
			return CertificateSignatureStrength.Forbidden;
		}
	}

	// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }, the only value that reader holds:
	// the algorithm, with a reader of the parameters, which holds nothing if there are none.
	// Throws AsnContentException if reader holds anything else.
	private static string ReadAlgorithmIdentifier(DerReader reader, out DerReader parameters)
	{
		reader.ThrowIfEmpty();
		DerReader identifier = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		string algorithm = identifier.ReadObjectIdentifier();
		parameters = identifier.HasData ? new DerReader(identifier.ReadEncodedValue()) : default;
		identifier.ThrowIfNotEmpty();
		return algorithm;
	}

	// MD2, MD4, MD5 and SHA-0, the OIW's sha, are Forbidden, SHA-1 and SHA-224 Weak; the others, as the identifier as a whole matched no SignatureAlgorithm, Unsupported.
	private static CertificateSignatureStrength GetHashStrength(string oid)
	{
		return oid switch
		{
			"1.2.840.113549.2.2" or "1.2.840.113549.2.4" or "1.2.840.113549.2.5" or "1.3.14.3.2.18" or "1.3.14.7.2.2.1" => CertificateSignatureStrength.Forbidden,
			Sha1Oid or "2.16.840.1.101.3.4.2.4" => CertificateSignatureStrength.Weak,
			_ => CertificateSignatureStrength.Unsupported
		};
	}
}
