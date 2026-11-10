namespace CryptoBase.X509;

/// <summary>
/// Represents a DistributionPoint of the CRL distribution points extension (RFC 5280, Sec. 4.2.1.13): where a CRL that covers a certificate may be found, for which reasons, and who issues it.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class CrlDistributionPoint
{
	private static readonly Asn1Tag ReasonsTag = new(TagClass.ContextSpecific, 1);
	private static readonly Asn1Tag CrlIssuerTag = new(TagClass.ContextSpecific, 2, true);

	private CrlDistributionPoint(DistributionPointName? distributionPoint, CrlReasonFlags? reasons, GeneralName[]? crlIssuer)
	{
		DistributionPoint = distributionPoint;
		Reasons = reasons;
		CrlIssuer = crlIssuer;

		if (crlIssuer is null)
		{
			CrlIssuerDirectoryNames = [];
			return;
		}

		List<ReadOnlyMemory<byte>> names = [];

		foreach (GeneralName name in crlIssuer)
		{
			if (name.Type is GeneralNameType.DirectoryName)
			{
				names.Add(name.Value);
			}
		}

		CrlIssuerDirectoryNames = names.AsReadOnly();
	}

	/// <summary>
	/// Gets the distributionPoint field, or <see langword="null" /> if it is absent.
	/// </summary>
	public DistributionPointName? DistributionPoint { get; }

	/// <summary>
	/// Gets the reasons field, or <see langword="null" /> if it is absent, which covers every reason.
	/// </summary>
	public CrlReasonFlags? Reasons { get; }

	/// <summary>
	/// Gets the DER encodings of the directoryName entries of the cRLIssuer field, in the order of the encoding; empty if there are none or the field is absent.
	/// </summary>
	public IReadOnlyList<ReadOnlyMemory<byte>> CrlIssuerDirectoryNames { get; }

	// cRLIssuer, every entry whatever its form, or null if it is absent.
	internal IReadOnlyList<GeneralName>? CrlIssuer { get; }

	// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint.
	internal static IReadOnlyList<CrlDistributionPoint> ReadList(ReadOnlyMemory<byte> value)
	{
		return DerReader.ReadSoleSequenceOf(value, Read).AsReadOnly();
	}

	// ReasonFlags ::= BIT STRING { unused (0), keyCompromise (1), …, aACompromise (8) }, under tag. Only the nine defined bits may be set; as with the key usage extension, trailing zero bits, which DER drops, are accepted.
	internal static CrlReasonFlags ReadReasons(ref DerReader reader, Asn1Tag tag)
	{
		return (CrlReasonFlags)DerReader.ReadNineNamedBits(reader.ReadBitString(tag, wholeBytes: false).Span);
	}

	// DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }, with implicit tags.
	private static CrlDistributionPoint Read(ref DerReader reader)
	{
		DerReader sequence = reader.ReadSequence();
		DistributionPointName? distributionPoint = DistributionPointName.ReadOptional(ref sequence);
		CrlReasonFlags? reasons = sequence.PeekTagIs(ReasonsTag) ? ReadReasons(ref sequence, ReasonsTag) : null;
		GeneralName[]? crlIssuer = sequence.PeekTagIs(CrlIssuerTag) ? GeneralName.ReadGeneralNames(ref sequence, CrlIssuerTag) : null;
		sequence.ThrowIfNotEmpty();

		if (distributionPoint is null && crlIssuer is null)
		{
			throw new AsnContentException("A distribution point has neither a distributionPoint nor a cRLIssuer.");
		}

		return new CrlDistributionPoint(distributionPoint, reasons, crlIssuer);
	}
}
