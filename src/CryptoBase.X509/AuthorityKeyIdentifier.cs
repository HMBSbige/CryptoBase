namespace CryptoBase.X509;

/// <summary>
/// Represents the value of an authority key identifier extension (RFC 5280, Sec. 4.2.1.1), which identifies the key that signed a certificate.
/// </summary>
/// <remarks>
/// <para>
/// Decoding accepts only DER and checks the structure of every field, including authorityCertIssuer, whose GeneralNames are checked as those of a subject alternative name, and authorityCertSerialNumber; this version does not expose those two fields.
/// </para>
/// <para>
/// An instance holds its own copy of the encoding, and the members return slices of it. Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class AuthorityKeyIdentifier
{
	internal static readonly Asn1Tag KeyIdentifierTag = new(TagClass.ContextSpecific, 0);
	private static readonly Asn1Tag AuthorityCertIssuerTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag AuthorityCertSerialNumberTag = new(TagClass.ContextSpecific, 2);

	private AuthorityKeyIdentifier(ReadOnlyMemory<byte>? keyIdentifier, GeneralName[]? authorityCertIssuer, ReadOnlyMemory<byte>? authorityCertSerialNumber)
	{
		KeyIdentifier = keyIdentifier;
		AuthorityCertIssuer = authorityCertIssuer;
		AuthorityCertSerialNumber = authorityCertSerialNumber;
	}

	/// <summary>
	/// Gets the keyIdentifier, the bytes of its OCTET STRING, or <see langword="null" /> if it is absent.
	/// </summary>
	/// <remarks>It equals the subject key identifier (RFC 5280, Sec. 4.2.1.2) of the issuer's certificate when the issuer follows RFC 5280; an empty value is a present but empty keyIdentifier.</remarks>
	public ReadOnlyMemory<byte>? KeyIdentifier { get; }

	// authorityCertIssuer, or null if it is absent.
	internal IReadOnlyList<GeneralName>? AuthorityCertIssuer { get; }

	// The contents of the INTEGER of authorityCertSerialNumber, as Certificate.SerialNumber, or null if it is absent.
	internal ReadOnlyMemory<byte>? AuthorityCertSerialNumber { get; }

	/// <summary>
	/// Decodes the DER-encoded value of an authority key identifier extension.
	/// </summary>
	/// <param name="source">The contents of extnValue, an AuthorityKeyIdentifier, with nothing after it.</param>
	/// <returns>The decoded value, which holds a copy of <paramref name="source" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="source" /> is not a DER-encoded AuthorityKeyIdentifier.</exception>
	public static AuthorityKeyIdentifier Decode(ReadOnlySpan<byte> source)
	{
		try
		{
			return Read(source.ToArray());
		}
		catch (AsnContentException e)
		{
			throw new ArgumentException("The authority key identifier is invalid.", nameof(source), e);
		}
	}

	// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL, authorityCertIssuer [1] GeneralNames OPTIONAL, authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }, with implicit tags; the results are slices of value.
	internal static AuthorityKeyIdentifier Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);

		// Each field is assigned only when present: a null in a conditional with a ReadOnlyMemory<byte> would convert, through byte[], to an empty value.
		ReadOnlyMemory<byte>? keyIdentifier = null;
		GeneralName[]? authorityCertIssuer = null;
		ReadOnlyMemory<byte>? authorityCertSerialNumber = null;

		if (sequence.PeekTagIs(KeyIdentifierTag))
		{
			keyIdentifier = sequence.ReadOctetString(KeyIdentifierTag);
		}

		if (sequence.PeekTagIs(AuthorityCertIssuerTag))
		{
			authorityCertIssuer = GeneralName.ReadGeneralNames(ref sequence, AuthorityCertIssuerTag);
		}

		if (sequence.PeekTagIs(AuthorityCertSerialNumberTag))
		{
			authorityCertSerialNumber = sequence.ReadIntegerBytes(AuthorityCertSerialNumberTag);
		}

		sequence.ThrowIfNotEmpty();
		return new AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer, authorityCertSerialNumber);
	}
}
