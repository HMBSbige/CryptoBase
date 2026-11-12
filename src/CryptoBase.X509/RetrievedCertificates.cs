namespace CryptoBase.X509;

// Reads what a caIssuers URI points to (RFC 5280, Sec. 4.2.2.1): a single DER certificate, or a BER or DER certs-only CMS message. The caller bounds the size of the input.
internal static class RetrievedCertificates
{
	private const string SignedDataOid = "1.2.840.113549.1.7.2";

	private static readonly Asn1Tag ContentTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, true);

	// The certificates, or null if the input is neither of the two, holds none or has more than maxElements elements in its certificates field; the certificates of a message that do not decode are left out, as they could not be issuers.
	public static Certificate[]? Read(ReadOnlyMemory<byte> data, int maxElements)
	{
		try
		{
			ValueAsnReader message = new(data.Span, AsnEncodingRules.BER);
			ValueAsnReader outer = message.ReadSequence();
			message.ThrowIfNotEmpty();

			// A Certificate starts with its TBSCertificate, and a ContentInfo with the type of its content.
			return outer.PeekTag() == Asn1Tag.ObjectIdentifier ? ReadCertsOnly(ref outer, maxElements) : [Certificate.Decode(data.Span)];
		}
		catch (Exception e) when (e is AsnContentException or ArgumentException)
		{
			return null;
		}
	}

	// ContentInfo ::= SEQUENCE { contentType ContentType, content [0] EXPLICIT ANY DEFINED BY contentType }, and SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms DigestAlgorithmIdentifiers, encapContentInfo EncapsulatedContentInfo, certificates [0] IMPLICIT CertificateSet OPTIONAL, ... } (RFC 5652, Secs. 3 and 5.1). The fields after certificates are not read: a certs-only message signs nothing, and the path checks each certificate.
	private static Certificate[]? ReadCertsOnly(ref ValueAsnReader contentInfo, int maxElements)
	{
		if (contentInfo.ReadObjectIdentifier() is not SignedDataOid)
		{
			return null;
		}

		ValueAsnReader content = contentInfo.ReadSequence(ContentTag);
		contentInfo.ThrowIfNotEmpty();
		ValueAsnReader signedData = content.ReadSequence();
		content.ThrowIfNotEmpty();
		signedData.ReadEncodedValue();
		signedData.ReadEncodedValue();
		signedData.ReadEncodedValue();

		if (!signedData.HasData || signedData.PeekTag() != CertificatesTag)
		{
			return null;
		}

		ValueAsnReader elements = signedData.ReadSetOf(CertificatesTag);
		List<Certificate> certificates = [];

		// CertificateChoices has other alternatives, with context-specific tags (RFC 5652, Sec. 10.2.2). Every element counts towards the limit, as each that fails to decode costs an exception.
		for (int count = 0; elements.HasData; ++count)
		{
			if (count == maxElements)
			{
				return null;
			}

			Asn1Tag tag = elements.PeekTag();
			ReadOnlySpan<byte> element = elements.ReadEncodedValue();

			if (tag != Asn1Tag.Sequence)
			{
				continue;
			}

			try
			{
				certificates.Add(Certificate.Decode(element));
			}
			catch (ArgumentException)
			{
			}
		}

		return certificates.Count > 0 ? [.. certificates] : null;
	}
}
