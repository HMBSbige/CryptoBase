namespace CryptoBase.Internal;

internal static class RsassaPssParameters
{
	internal const string Mgf1Oid = "1.2.840.113549.1.1.8";

	private static readonly Asn1Tag HashAlgorithmTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag MaskGenAlgorithmTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag SaltLengthTag = new(TagClass.ContextSpecific, 2, true);
	private static readonly Asn1Tag TrailerFieldTag = new(TagClass.ContextSpecific, 3, true);

	// RSASSA-PSS-params (RFC 4055, Sec. 3.1), whose fields default to SHA-1, MGF1 with SHA-1, a saltLength of 20 and the trailer field 1, as the RSASSA-PSS algorithm of their hash, its length in bytes and the saltLength.
	// They name one if the hash is SHA-256, SHA-384 or SHA-512, MGF1 has the same hash, each hash AlgorithmIdentifier has NULL or absent parameters (Sec. 2.1), the saltLength is not negative and the trailer field is 1;
	// otherwise the result is false. A field with its default value is accepted, as Sec. 3.1 requires of the trailer field. Throws AsnContentException if the parameters are not DER.
	internal static bool TryRead(ReadOnlySpan<byte> parameters, out SignatureAlgorithm algorithm, out int hashLength, out int saltLength)
	{
		ValueAsnReader reader = new(parameters, AsnEncodingRules.DER);
		ValueAsnReader fields = reader.ReadSequence();
		reader.ThrowIfNotEmpty();
		(algorithm, hashLength) = (default, 0);
		(SignatureAlgorithm maskAlgorithm, int trailerField) = (default, 1);
		saltLength = 20;

		if (fields.PeekTagIs(HashAlgorithmTag))
		{
			ValueAsnReader field = fields.ReadSequence(HashAlgorithmTag);
			(algorithm, hashLength) = ReadHashAlgorithm(ref field);
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(MaskGenAlgorithmTag))
		{
			ValueAsnReader field = fields.ReadSequence(MaskGenAlgorithmTag);
			ValueAsnReader maskGenAlgorithm = field.ReadSequence();
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
			ValueAsnReader field = fields.ReadSequence(SaltLengthTag);
			saltLength = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		if (fields.PeekTagIs(TrailerFieldTag))
		{
			ValueAsnReader field = fields.ReadSequence(TrailerFieldTag);
			trailerField = field.ReadInt32();
			field.ThrowIfNotEmpty();
		}

		fields.ThrowIfNotEmpty();
		return algorithm is not default(SignatureAlgorithm) && maskAlgorithm == algorithm && saltLength >= 0 && trailerField is 1;
	}

	// A hash AlgorithmIdentifier, as the RSASSA-PSS algorithm of the hash and its length, or default for another hash or parameters other than NULL.
	private static (SignatureAlgorithm Algorithm, int HashLength) ReadHashAlgorithm(ref ValueAsnReader reader)
	{
		ValueAsnReader contents = reader.ReadSequence();
		string oid = contents.ReadObjectIdentifier();
		ReadOnlySpan<byte> parameters = contents.HasData ? contents.ReadEncodedValue() : default;
		contents.ThrowIfNotEmpty();

		if (parameters is not ([] or [0x05, 0x00]))
		{
			return default;
		}

		return oid switch
		{
			"2.16.840.1.101.3.4.2.1" => (SignatureAlgorithm.RsaPssSha256, 32),
			"2.16.840.1.101.3.4.2.2" => (SignatureAlgorithm.RsaPssSha384, 48),
			"2.16.840.1.101.3.4.2.3" => (SignatureAlgorithm.RsaPssSha512, 64),
			_ => default
		};
	}
}
