namespace CryptoBase.X509;

// The extensions that Certificate decodes on first use rather than when it decodes the certificate, so that an error in one appears only to the caller that asks for it. The values are slices of the certificate's memory, and the instance is immutable.
internal sealed class DecodedExtensions
{
	internal const string SubjectKeyIdentifierOid = "2.5.29.14";
	private const string SubjectAlternativeNameOid = "2.5.29.17";
	private const string BasicConstraintsOid = "2.5.29.19";
	private const string NameConstraintsOid = "2.5.29.30";
	private const string CertificatePoliciesOid = "2.5.29.32";
	private const string PolicyMappingsOid = "2.5.29.33";
	internal const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string PolicyConstraintsOid = "2.5.29.36";
	private const string ExtendedKeyUsageOid = "2.5.29.37";
	private const string InhibitAnyPolicyOid = "2.5.29.54";

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
				case CertificatePoliciesOid:
				{
					CertificatePolicies = DecodedExtension<CertificatePolicies>.Decode(extension.Value, X509.CertificatePolicies.Read);
					break;
				}
				case PolicyMappingsOid:
				{
					PolicyMappings = DecodedExtension<PolicyMappings>.Decode(extension.Value, X509.PolicyMappings.Read);
					break;
				}
				case PolicyConstraintsOid:
				{
					PolicyConstraints = DecodedExtension<PolicyConstraints>.Decode(extension.Value, X509.PolicyConstraints.Read);
					break;
				}
				case InhibitAnyPolicyOid:
				{
					InhibitAnyPolicy = DecodedExtension<int?>.Decode(extension.Value, static value => X509.PolicyConstraints.ReadInhibitAnyPolicy(value));
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

	public DecodedExtension<CertificatePolicies> CertificatePolicies { get; }

	public DecodedExtension<PolicyMappings> PolicyMappings { get; }

	public DecodedExtension<PolicyConstraints> PolicyConstraints { get; }

	public DecodedExtension<int?> InhibitAnyPolicy { get; }

	// SubjectKeyIdentifier ::= KeyIdentifier, and KeyIdentifier ::= OCTET STRING (RFC 5280, Sec. 4.2.1.2).
	private static ReadOnlyMemory<byte> ReadSubjectKeyIdentifier(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		ReadOnlyMemory<byte> keyIdentifier = reader.ReadOctetString();
		reader.ThrowIfNotEmpty();
		return keyIdentifier;
	}
}
