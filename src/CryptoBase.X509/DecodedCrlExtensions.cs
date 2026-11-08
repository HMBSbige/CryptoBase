namespace CryptoBase.X509;

// The extensions that CertificateRevocationList decodes on first use, so that an error in one appears only to the caller that asks for it. The values are slices of the CRL's memory, and the instance is immutable.
internal sealed class DecodedCrlExtensions
{
	private const string AuthorityKeyIdentifierOid = "2.5.29.35";
	private const string CrlNumberOid = "2.5.29.20";
	private const string DeltaCrlIndicatorOid = "2.5.29.27";
	private const string IssuingDistributionPointOid = "2.5.29.28";

	// CertificateRevocationList allows each extension once.
	public DecodedCrlExtensions(IReadOnlyList<CertificateExtension> extensions)
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
				case CrlNumberOid:
				{
					CrlNumber = DecodedExtension<ReadOnlyMemory<byte>?>.Decode(extension.Value, static value => ReadCrlNumber(value));
					break;
				}
				case DeltaCrlIndicatorOid:
				{
					DeltaCrlIndicator = DecodedExtension<ReadOnlyMemory<byte>?>.Decode(extension.Value, static value => ReadCrlNumber(value));
					break;
				}
				case IssuingDistributionPointOid:
				{
					IssuingDistributionPoint = DecodedExtension<IssuingDistributionPoint>.Decode(extension.Value, X509.IssuingDistributionPoint.Read);
					break;
				}
			}
		}
	}

	public DecodedExtension<AuthorityKeyIdentifier> AuthorityKeyIdentifier { get; }

	public DecodedExtension<ReadOnlyMemory<byte>?> CrlNumber { get; }

	public DecodedExtension<ReadOnlyMemory<byte>?> DeltaCrlIndicator { get; }

	public DecodedExtension<IssuingDistributionPoint> IssuingDistributionPoint { get; }

	// CRLNumber ::= INTEGER (0..MAX) (RFC 5280, Sec. 5.2.3), and BaseCRLNumber ::= CRLNumber (Sec. 5.2.4). A value longer than the 20 octets that conforming issuers keep to is accepted, as nothing computes with it.
	private static ReadOnlyMemory<byte> ReadCrlNumber(ReadOnlyMemory<byte> value)
	{
		DerReader reader = new(value);
		ReadOnlyMemory<byte> number = reader.ReadIntegerBytes();
		reader.ThrowIfNotEmpty();

		if (number.Span[0] >= 0x80)
		{
			throw new AsnContentException("The CRL number is negative.");
		}

		return number;
	}
}
