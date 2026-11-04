namespace CryptoBase.X509;

/// <summary>
/// Represents an AlgorithmIdentifier (RFC 5280, Sec. 4.1.1.2): an algorithm and its parameters.
/// </summary>
public sealed class AlgorithmIdentifier
{
	internal const string RsassaPssOid = "1.2.840.113549.1.1.10";

	private const string Mgf1Oid = "1.2.840.113549.1.1.8";

	private static readonly Asn1Tag HashAlgorithmTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag MaskGenAlgorithmTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag SaltLengthTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag TrailerFieldTag = new(TagClass.ContextSpecific, 3, true);

	// The identifiers that FromSignatureAlgorithm gives: ecdsa-with-SHA256, -SHA384 and -SHA512 without parameters (RFC 5758, Sec. 3.2); sha256WithRSAEncryption, sha384WithRSAEncryption and sha512WithRSAEncryption with NULL parameters (RFC 4055, Sec. 5);
	// id-RSASSA-PSS with the RSASSA-PSS-params of each hash (RFC 4055, Sec. 3.1); id-Ed25519 and id-Ed448 without parameters (RFC 8410, Sec. 6); and id-ml-dsa-44, -65 and -87 without parameters (RFC 9881).
	private static readonly (SignatureAlgorithm Algorithm, AlgorithmIdentifier Identifier)[] SignatureAlgorithms =
	[
		(SignatureAlgorithm.RsaPkcs1Sha256, FromDer([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00])),
		(SignatureAlgorithm.RsaPkcs1Sha384, FromDer([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00])),
		(SignatureAlgorithm.RsaPkcs1Sha512, FromDer([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0x05, 0x00])),
		(SignatureAlgorithm.RsaPssSha256, FromDer(RsassaPss(0x01, 32))),
		(SignatureAlgorithm.RsaPssSha384, FromDer(RsassaPss(0x02, 48))),
		(SignatureAlgorithm.RsaPssSha512, FromDer(RsassaPss(0x03, 64))),
		(SignatureAlgorithm.EcdsaSha256, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])),
		(SignatureAlgorithm.EcdsaSha384, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03])),
		(SignatureAlgorithm.EcdsaSha512, FromDer([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04])),
		(SignatureAlgorithm.Ed25519, FromDer([0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])),
		(SignatureAlgorithm.Ed448, FromDer([0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x71])),
		(SignatureAlgorithm.MLDsa44, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11])),
		(SignatureAlgorithm.MLDsa65, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])),
		(SignatureAlgorithm.MLDsa87, FromDer([0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13])),
	];

	private AlgorithmIdentifier(string oid, ReadOnlyMemory<byte> parameters, ReadOnlyMemory<byte> encoded)
	{
		Oid = oid;
		Parameters = parameters;
		Encoded = encoded;
	}

	/// <summary>
	/// Gets the algorithm as a dotted-decimal object identifier.
	/// </summary>
	public string Oid { get; }

	/// <summary>
	/// Gets the DER encoding of the parameters, or an empty value if they are absent.
	/// </summary>
	public ReadOnlyMemory<byte> Parameters { get; }

	/// <summary>
	/// Gets the DER encoding of the whole AlgorithmIdentifier.
	/// </summary>
	public ReadOnlyMemory<byte> Encoded { get; }

	/// <summary>
	/// Gets the identifier that names a signature algorithm in X.509.
	/// </summary>
	/// <remarks>
	/// ECDSA, Ed25519, Ed448 and ML-DSA identifiers have no parameters (RFC 5758, Sec. 3.2; RFC 8410, Sec. 6; RFC 9881), and RSASSA-PKCS1-v1_5 identifiers have NULL parameters (RFC 4055, Sec. 5).
	/// An RSASSA-PSS identifier is id-RSASSA-PSS with RSASSA-PSS-params (RFC 4055, Sec. 3.1) that name the hash, MGF1 with the hash, and a saltLength as long as the hash, and omit the default trailer field; the hash AlgorithmIdentifiers have NULL parameters, as RFC 4055, Sec. 2.1, defines them.
	/// </remarks>
	/// <param name="algorithm">The signature algorithm: one of <see cref="SignatureAlgorithm.RsaPkcs1Sha256" /> to <see cref="SignatureAlgorithm.RsaPssSha512" />, <see cref="SignatureAlgorithm.EcdsaSha256" />, <see cref="SignatureAlgorithm.EcdsaSha384" />, <see cref="SignatureAlgorithm.EcdsaSha512" />, <see cref="SignatureAlgorithm.Ed25519" />, <see cref="SignatureAlgorithm.Ed448" />, <see cref="SignatureAlgorithm.MLDsa44" />, <see cref="SignatureAlgorithm.MLDsa65" /> or <see cref="SignatureAlgorithm.MLDsa87" />.</param>
	/// <returns>The identifier.</returns>
	/// <exception cref="NotSupportedException"><paramref name="algorithm" /> is another value.</exception>
	public static AlgorithmIdentifier FromSignatureAlgorithm(SignatureAlgorithm algorithm)
	{
		foreach ((SignatureAlgorithm candidate, AlgorithmIdentifier identifier) in SignatureAlgorithms)
		{
			if (candidate == algorithm)
			{
				return identifier;
			}
		}

		throw new NotSupportedException($"The signature algorithm {algorithm} has no X.509 identifier in this version.");
	}

	/// <summary>
	/// Determines the signature algorithm that the identifier names.
	/// </summary>
	/// <remarks>
	/// <para>
	/// An ECDSA, Ed25519, Ed448 or ML-DSA identifier matches only in the DER that the specification of the algorithm requires, without parameters.
	/// An RSASSA-PKCS1-v1_5 identifier, sha256WithRSAEncryption, sha384WithRSAEncryption or sha512WithRSAEncryption, matches with NULL or absent parameters, as RFC 4055, Sec. 5, requires.
	/// </para>
	/// <para>
	/// An id-RSASSA-PSS identifier matches with DER-encoded RSASSA-PSS-params (RFC 4055, Sec. 3.1) that name SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, a saltLength as long as the hash and the trailer field 1, the only combinations that <see cref="SignatureAlgorithm" /> defines.
	/// As RFC 4055 requires, each hash AlgorithmIdentifier may have NULL or absent parameters (Sec. 2.1), and the trailer field may be present as well as absent (Sec. 3.1); identifiers without parameters, which name no hash, do not match.
	/// </para>
	/// </remarks>
	/// <param name="algorithm">When this method returns <see langword="true" />, the signature algorithm.</param>
	/// <returns><see langword="true" /> if the identifier names a signature algorithm that <see cref="FromSignatureAlgorithm" /> accepts; otherwise, <see langword="false" />.</returns>
	public bool TryGetSignatureAlgorithm(out SignatureAlgorithm algorithm)
	{
		ReadOnlySpan<byte> encoded = Encoded.Span;

		foreach ((SignatureAlgorithm candidate, AlgorithmIdentifier identifier) in SignatureAlgorithms)
		{
			if (encoded.SequenceEqual(identifier.Encoded.Span))
			{
				algorithm = candidate;
				return true;
			}
		}

		algorithm = Oid switch
		{
			"1.2.840.113549.1.1.11" when Parameters.IsEmpty => SignatureAlgorithm.RsaPkcs1Sha256,
			"1.2.840.113549.1.1.12" when Parameters.IsEmpty => SignatureAlgorithm.RsaPkcs1Sha384,
			"1.2.840.113549.1.1.13" when Parameters.IsEmpty => SignatureAlgorithm.RsaPkcs1Sha512,
			RsassaPssOid => ReadRsassaPssSignatureAlgorithm(Parameters),
			_ => default
		};

		return algorithm is not default(SignatureAlgorithm);
	}

	// SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }; the results are slices of the reader's memory.
	internal static AlgorithmIdentifier Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence(out ReadOnlyMemory<byte> encoded);
		string oid = contents.ReadObjectIdentifier();
		ReadOnlyMemory<byte> parameters = contents.HasData ? contents.ReadEncodedValue() : default;
		contents.ThrowIfNotEmpty();
		return new AlgorithmIdentifier(oid, parameters, encoded);
	}

	// RSASSA-PSS-params (RFC 4055, Sec. 3.1), whose fields default to SHA-1, MGF1 with SHA-1, a saltLength of 20 and the trailer field 1, as the RSASSA-PSS algorithm of their hash, its length in bytes and the saltLength.
	// They name one if the hash is SHA-256, SHA-384 or SHA-512, MGF1 has the same hash, each hash AlgorithmIdentifier has NULL or absent parameters (Sec. 2.1), the saltLength is not negative and the trailer field is 1;
	// otherwise the result is false. A field with its default value is accepted, as Sec. 3.1 requires of the trailer field. Throws AsnContentException if the parameters are not DER.
	internal static bool TryReadRsassaPssParameters(ReadOnlyMemory<byte> parameters, out SignatureAlgorithm algorithm, out int hashLength, out int saltLength)
	{
		DerReader reader = new(parameters);
		DerReader fields = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		(algorithm, hashLength) = (default, 0);
		(SignatureAlgorithm maskAlgorithm, int trailerField) = (default, 1);
		saltLength = 20;

		if (fields.PeekTagIs(HashAlgorithmTag))
		{
			DerReader field = fields.ReadSequence(HashAlgorithmTag);
			(algorithm, hashLength) = ReadHashAlgorithm(ref field);
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(MaskGenAlgorithmTag))
		{
			DerReader field = fields.ReadSequence(MaskGenAlgorithmTag);
			DerReader maskGenAlgorithm = field.ReadSequence();
			field.ThrowIfNotEmpty();

			if (maskGenAlgorithm.ReadObjectIdentifier() is Mgf1Oid)
			{
				(maskAlgorithm, _) = ReadHashAlgorithm(ref maskGenAlgorithm);
			}
			else if (maskGenAlgorithm.HasData)
			{
				maskGenAlgorithm.ReadEncodedValue();
			}

			maskGenAlgorithm.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(SaltLengthTag))
		{
			DerReader field = fields.ReadSequence(SaltLengthTag);
			saltLength = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(TrailerFieldTag))
		{
			DerReader field = fields.ReadSequence(TrailerFieldTag);
			trailerField = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		fields.ThrowIfNotEmpty();
		return algorithm is not default(SignatureAlgorithm) && maskAlgorithm == algorithm && saltLength >= 0 && trailerField is 1;
	}

	private static AlgorithmIdentifier FromDer(byte[] encoded)
	{
		DerReader reader = new(encoded);
		AlgorithmIdentifier identifier = Read(ref reader);
		reader.ThrowIfNotEmpty();
		return identifier;
	}

	// id-RSASSA-PSS with RSASSA-PSS-params { sha2Identifier, mgf1Sha2Identifier, saltLength }, where the last byte of id-sha256, -sha384 or -sha512 is hash.
	private static byte[] RsassaPss(byte hash, byte saltLength)
	{
		return
		[
			0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34,
			0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, hash, 0x05, 0x00,
			0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, hash, 0x05, 0x00,
			0xA2, 0x03, 0x02, 0x01, saltLength
		];
	}

	// The RSASSA-PSS algorithm that a signature's parameters name, whose salt is as long as the hash, or default.
	private static SignatureAlgorithm ReadRsassaPssSignatureAlgorithm(ReadOnlyMemory<byte> parameters)
	{
		try
		{
			return TryReadRsassaPssParameters(parameters, out SignatureAlgorithm algorithm, out int hashLength, out int saltLength) && saltLength == hashLength ? algorithm : default;
		}
		catch (AsnContentException)
		{
			return default;
		}
	}

	// A hash AlgorithmIdentifier, as the RSASSA-PSS algorithm of the hash and its length, or default for another hash or parameters other than NULL.
	private static (SignatureAlgorithm Algorithm, int HashLength) ReadHashAlgorithm(ref DerReader reader)
	{
		AlgorithmIdentifier hash = Read(ref reader);

		return hash switch
		{
			{ Parameters.Span: not ([] or [0x05, 0x00]) } => default,
			{ Oid: "2.16.840.1.101.3.4.2.1" } => (SignatureAlgorithm.RsaPssSha256, 32),
			{ Oid: "2.16.840.1.101.3.4.2.2" } => (SignatureAlgorithm.RsaPssSha384, 48),
			{ Oid: "2.16.840.1.101.3.4.2.3" } => (SignatureAlgorithm.RsaPssSha512, 64),
			_ => default
		};
	}
}
