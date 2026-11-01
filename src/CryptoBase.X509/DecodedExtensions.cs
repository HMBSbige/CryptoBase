namespace CryptoBase.X509;

// The extensions that Certificate decodes on first use rather than when it decodes the certificate, so that an error in one appears only to the caller that asks for it. The values are slices of the certificate's memory, and the instance is immutable.
internal sealed class DecodedExtensions
{
	private const string SubjectKeyIdentifierOid = "2.5.29.14";
	private const string SubjectAlternativeNameOid = "2.5.29.17";
	private const string BasicConstraintsOid = "2.5.29.19";
	private const string NameConstraintsOid = "2.5.29.30";
	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string ExtendedKeyUsageOid = "2.5.29.37";

	// Certificate allows each extension once.
	public DecodedExtensions(IReadOnlyList<CertificateExtension> extensions)
	{
		// Indexed, as an enumerator of the interface would be allocated.
		for (int i = 0; i < extensions.Count; ++i)
		{
			CertificateExtension extension = extensions[i];

			switch (extension.Oid)
			{
				case AuthorityKeyIdentifierOid:
				{
					AuthorityKeyIdentifier = DecodedExtension<AuthorityKeyIdentifier>.Decode(extension.Value, X509.AuthorityKeyIdentifier.Read);
					break;
				}
				case SubjectKeyIdentifierOid:
				{
					SubjectKeyIdentifier = DecodedExtension<ReadOnlyMemory<byte>?>.Decode(extension.Value, static value => ReadSubjectKeyIdentifier(value));
					break;
				}
				case SubjectAlternativeNameOid:
				{
					SubjectAlternativeName = DecodedExtension<SubjectAlternativeName>.Decode(extension.Value, X509.SubjectAlternativeName.Read);
					break;
				}
				case BasicConstraintsOid:
				{
					BasicConstraints = DecodedExtension<BasicConstraints>.Decode(extension.Value, X509.BasicConstraints.Read);
					break;
				}
				case ExtendedKeyUsageOid:
				{
					ExtendedKeyUsage = DecodedExtension<ExtendedKeyUsage>.Decode(extension.Value, X509.ExtendedKeyUsage.Read);
					break;
				}
				case NameConstraintsOid:
				{
					NameConstraints = DecodedExtension<NameConstraints>.Decode(extension.Value, X509.NameConstraints.Read);
					break;
				}
			}
		}
	}

	public DecodedExtension<AuthorityKeyIdentifier> AuthorityKeyIdentifier { get; }

	public DecodedExtension<ReadOnlyMemory<byte>?> SubjectKeyIdentifier { get; }

	public DecodedExtension<SubjectAlternativeName> SubjectAlternativeName { get; }

	public DecodedExtension<BasicConstraints> BasicConstraints { get; }

	public DecodedExtension<ExtendedKeyUsage> ExtendedKeyUsage { get; }

	public DecodedExtension<NameConstraints> NameConstraints { get; }

	// SubjectKeyIdentifier ::= KeyIdentifier, and KeyIdentifier ::= OCTET STRING (RFC 5280, Sec. 4.2.1.2).
	private static ReadOnlyMemory<byte> ReadSubjectKeyIdentifier(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		ReadOnlyMemory<byte> keyIdentifier = reader.ReadOctetString();
		reader.ThrowIfNotEmpty();
		return keyIdentifier;
	}
}
