namespace CryptoBase.X509;

// The algorithms and keys that TrustAnchorCertificateValidator accepts in a certification path.
internal static class CertificatePolicy
{
	public const int MaxRsaKeySize = 16384;

	private const int MaxRsaPublicExponentSize = 33;
	private const string ECPublicKeyOid = "1.2.840.10045.2.1";
	private const string DsaOid = "1.2.840.10040.4.1";

	private static readonly Asn1Tag HashAlgorithmTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag MaskGenAlgorithmTag = new(TagClass.ContextSpecific, 1, true);

	// The named curves P-256, P-384 and P-521 (RFC 5480, Sec. 2.1.1.1), as the DER of the parameters of id-ecPublicKey.
	private static ReadOnlySpan<byte> P256 => [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

	private static ReadOnlySpan<byte> P384 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

	private static ReadOnlySpan<byte> P521 => [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

	// The named curve of SM2, 1.2.156.10197.1.301 (GB/T 35275-2017), with which id-ecPublicKey names an SM2 key.
	private static ReadOnlySpan<byte> SM2 => [0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D];

	// Whether a certificate's signature can be verified: null for an algorithm that AlgorithmIdentifier names, WeakAlgorithm for one that the policy refuses whatever the key, and UnsupportedAlgorithm for any other.
	// MD2, MD4 and MD5 are forbidden, and SHA-1, SHA-224 and DSA refused, as SignatureAlgorithm has none of them: RSASSA-PKCS1-v1_5 and ECDSA with those hashes, the OIW identifiers, RSASSA-PSS whose hash or MGF1 hash is one of them, the default SHA-1 included, and DSA with any hash.
	public static CertificateValidationError? CheckSignatureAlgorithm(AlgorithmIdentifier identifier)
	{
		if (identifier.TryGetSignatureAlgorithm(out _))
		{
			return null;
		}

		bool weak = identifier.Oid switch
		{
			// md2WithRSAEncryption, md4WithRSAEncryption, md5WithRSAEncryption, sha1WithRSAEncryption and sha224WithRSAEncryption.
			"1.2.840.113549.1.1.2" or "1.2.840.113549.1.1.3" or "1.2.840.113549.1.1.4" or "1.2.840.113549.1.1.5" or "1.2.840.113549.1.1.14" => true,
			// The OIW's md4WithRSA, md5WithRSA, md4WithRSAEncryption, shaWithRSAEncryption, md2WithRSASignature, md5WithRSASignature and sha1WithRSASignature.
			"1.3.14.3.2.2" or "1.3.14.3.2.3" or "1.3.14.3.2.4" or "1.3.14.3.2.15" or "1.3.14.3.2.24" or "1.3.14.3.2.25" or "1.3.14.3.2.29" => true,
			// ecdsa-with-SHA1 and ecdsa-with-SHA224.
			"1.2.840.10045.4.1" or "1.2.840.10045.4.3.1" => true,
			// dsa-with-sha1, the OIW's dsaWithSHA, dsaCommonWithSHA, dsaWithSHA1 and dsaCommonWithSHA1, and NIST's DSA with SHA-2 (RFC 5758, Sec. 3.1) and SHA-3.
			"1.2.840.10040.4.3" or "1.3.14.3.2.13" or "1.3.14.3.2.21" or "1.3.14.3.2.27" or "1.3.14.3.2.28" => true,
			"2.16.840.1.101.3.4.3.1" or "2.16.840.1.101.3.4.3.2" or "2.16.840.1.101.3.4.3.3" or "2.16.840.1.101.3.4.3.4" => true,
			"2.16.840.1.101.3.4.3.5" or "2.16.840.1.101.3.4.3.6" or "2.16.840.1.101.3.4.3.7" or "2.16.840.1.101.3.4.3.8" => true,
			AlgorithmIdentifier.RsassaPssOid => HasWeakPssHash(identifier.Parameters),
			_ => false
		};

		return weak ? CertificateValidationError.WeakAlgorithm : CertificateValidationError.UnsupportedAlgorithm;
	}

	// Whether the policy accepts a public key, before it is imported: null if so or if the importer decides, and otherwise the reason, with its description in reason.
	// RSA keys need a modulus of minRsaKeySize to 16384 bits that is a multiple of 8, as CA/Browser Forum Baseline Requirements, Sec. 6.1.5, require, and a public exponent of at most 33 bits, which bound the work of a verification;
	// EC keys a named curve, P-256, P-384, P-521 or that of SM2, with explicit parameters not supported (RFC 5480, Sec. 2.1.1); and DSA keys are refused.
	public static CertificateValidationError? CheckPublicKey(SubjectPublicKeyInfo info, int minRsaKeySize, out string? reason)
	{
		switch (info.Algorithm.Oid)
		{
			case AlgorithmIdentifier.RsaEncryptionOid or AlgorithmIdentifier.RsassaPssOid:
			{
				return CheckRsaPublicKey(info.PublicKey, minRsaKeySize, out reason);
			}
			case ECPublicKeyOid:
			{
				ReadOnlySpan<byte> parameters = info.Algorithm.Parameters.Span;

				if (parameters.SequenceEqual(P256) || parameters.SequenceEqual(P384) || parameters.SequenceEqual(P521) || parameters.SequenceEqual(SM2))
				{
					break;
				}

				// A namedCurve other than these; specifiedCurve and implicitCurve, which RFC 5480 forbids, are not supported.
				if (parameters is [0x06, ..])
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
	public static bool IsRsa(AlgorithmIdentifier identifier)
	{
		return identifier.Oid is AlgorithmIdentifier.RsaEncryptionOid or AlgorithmIdentifier.RsassaPssOid;
	}

	// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 8017, Appendix A.1.1), whose integers are positive; an odd modulus and an odd exponent of at least 3 (RFC 8017, Sec. 3.1) make a valid key.
	private static CertificateValidationError? CheckRsaPublicKey(ReadOnlyMemory<byte> publicKey, int minRsaKeySize, out string? reason)
	{
		ReadOnlySpan<byte> modulus;
		ReadOnlySpan<byte> exponent;

		try
		{
			DerReader sequence = DerReader.ReadSoleSequence(publicKey);
			modulus = sequence.ReadIntegerBytes().Span;
			exponent = sequence.ReadIntegerBytes().Span;
			sequence.ThrowIfNotEmpty();
		}
		catch (AsnContentException)
		{
			reason = "has an RSA key that does not decode";
			return CertificateValidationError.Malformed;
		}

		// A negative INTEGER starts with a set high bit; DER encodes zero as one zero octet.
		bool negative = modulus[0] >= 0x80 || exponent[0] >= 0x80;
		modulus = TrimLeadingZero(modulus);
		exponent = TrimLeadingZero(exponent);

		if (negative || (modulus[^1] & 1) is 0 || (exponent[^1] & 1) is 0 || exponent is [1])
		{
			reason = "has an RSA key whose modulus or public exponent is invalid";
			return CertificateValidationError.Malformed;
		}

		int modulusBits = GetBitLength(modulus);

		if (modulusBits < minRsaKeySize || modulusBits > MaxRsaKeySize || modulusBits % 8 is not 0)
		{
			reason = $"has an RSA key of {modulusBits} bits; the policy requires a multiple of 8 from {minRsaKeySize} to {MaxRsaKeySize}";
			return CertificateValidationError.WeakAlgorithm;
		}

		if (GetBitLength(exponent) > MaxRsaPublicExponentSize)
		{
			reason = $"has an RSA key whose public exponent has more than {MaxRsaPublicExponentSize} bits";
			return CertificateValidationError.WeakAlgorithm;
		}

		reason = null;
		return null;
	}

	// RSASSA-PSS-params (RFC 4055, Sec. 3.1), whose hash and MGF1 hash default to SHA-1, name a hash that the policy refuses; parameters that do not decode name none.
	private static bool HasWeakPssHash(ReadOnlyMemory<byte> parameters)
	{
		if (parameters.IsEmpty)
		{
			return true;
		}

		try
		{
			DerReader fields = DerReader.ReadSoleSequence(parameters);
			string hash = "1.3.14.3.2.26";
			string maskHash = hash;

			if (fields.PeekTagIs(HashAlgorithmTag))
			{
				DerReader field = fields.ReadSequence(HashAlgorithmTag);
				hash = field.ReadSequence().ReadObjectIdentifier();
			}

			if (fields.PeekTagIs(MaskGenAlgorithmTag))
			{
				DerReader field = fields.ReadSequence(MaskGenAlgorithmTag);
				DerReader maskGenAlgorithm = field.ReadSequence();
				maskHash = maskGenAlgorithm.ReadObjectIdentifier() is AlgorithmIdentifier.Mgf1Oid ? maskGenAlgorithm.ReadSequence().ReadObjectIdentifier() : "";
			}

			return IsWeakHash(hash) || IsWeakHash(maskHash);
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	// MD2, MD4, MD5, SHA-1 and SHA-224.
	private static bool IsWeakHash(string oid)
	{
		return oid is "1.2.840.113549.2.2" or "1.2.840.113549.2.4" or "1.2.840.113549.2.5" or "1.3.14.3.2.26" or "2.16.840.1.101.3.4.2.4";
	}

	// The minimal big-endian bytes of a positive INTEGER, which DER prefixes with a zero byte when the high bit is set.
	private static ReadOnlySpan<byte> TrimLeadingZero(ReadOnlySpan<byte> value)
	{
		return value is [0x00, >= 0x80, ..] ? value.Slice(1) : value;
	}

	// Of a nonempty value without leading zeros.
	private static int GetBitLength(ReadOnlySpan<byte> value)
	{
		return 8 * value.Length - System.Numerics.BitOperations.LeadingZeroCount(value[0]) + 24;
	}
}
