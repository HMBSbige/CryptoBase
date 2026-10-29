namespace CryptoBase.X509;

/// <summary>
/// Represents a certificate extension (RFC 5280, Sec. 4.1.2.9): its identifier, its criticality and its value.
/// </summary>
public sealed class CertificateExtension
{
	/// <summary>
	/// Initializes an extension.
	/// </summary>
	/// <param name="oid">The extension identifier, as a dotted-decimal object identifier.</param>
	/// <param name="critical"><see langword="true" /> if a certificate user that does not recognize the extension must reject the certificate; otherwise, <see langword="false" />.</param>
	/// <param name="value">The contents of extnValue, usually the DER encoding of the extension's ASN.1 type; the instance holds a copy.</param>
	/// <exception cref="ArgumentNullException"><paramref name="oid" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="oid" /> is not a valid object identifier.</exception>
	public CertificateExtension(string oid, bool critical, ReadOnlySpan<byte> value)
	{
		ArgumentNullException.ThrowIfNull(oid);

		try
		{
			new AsnWriter(AsnEncodingRules.DER).WriteObjectIdentifier(oid);
		}
		catch (ArgumentException e)
		{
			throw new ArgumentException("The object identifier is invalid.", nameof(oid), e);
		}

		Oid = oid;
		Critical = critical;
		Value = value.ToArray();
	}

	private CertificateExtension(string oid, bool critical, ReadOnlyMemory<byte> value)
	{
		Oid = oid;
		Critical = critical;
		Value = value;
	}

	/// <summary>
	/// Gets the extension identifier as a dotted-decimal object identifier.
	/// </summary>
	public string Oid { get; }

	/// <summary>
	/// Gets a value that indicates whether a certificate user that does not recognize the extension must reject the certificate.
	/// </summary>
	public bool Critical { get; }

	/// <summary>
	/// Gets the contents of extnValue.
	/// </summary>
	public ReadOnlyMemory<byte> Value { get; }

	// Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }; DER omits critical when it is FALSE. The value is a slice of the reader's memory.
	internal static CertificateExtension Read(ref DerReader reader)
	{
		DerReader contents = reader.ReadSequence();
		string oid = contents.ReadObjectIdentifier();
		bool critical = contents.PeekTagIs(Asn1Tag.Boolean);

		if (critical && !contents.ReadBoolean())
		{
			throw new AsnContentException();
		}

		ReadOnlyMemory<byte> value = contents.ReadOctetString();
		contents.ThrowIfNotEmpty();
		return new CertificateExtension(oid, critical, value);
	}

	internal void Write(AsnWriter writer)
	{
		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier(Oid);

			if (Critical)
			{
				writer.WriteBoolean(true);
			}

			writer.WriteOctetString(Value.Span);
		}
	}
}
