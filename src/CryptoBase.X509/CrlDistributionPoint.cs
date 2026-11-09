namespace CryptoBase.X509;

/// <summary>
/// Represents a DistributionPoint of the CRL distribution points extension (RFC 5280, Sec. 4.2.1.13): where a CRL that covers a certificate may be found, for which reasons, and who issues it.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class CrlDistributionPoint
{
	private static readonly Asn1Tag DistributionPointTag = new(TagClass.ContextSpecific, 0, true);
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
		DerReader sequence = DerReader.ReadSoleSequence(value);
		sequence.ThrowIfEmpty();
		List<CrlDistributionPoint> points = [];

		while (sequence.HasData)
		{
			points.Add(Read(ref sequence));
		}

		return points.AsReadOnly();
	}

	// ReasonFlags ::= BIT STRING { unused (0), keyCompromise (1), …, aACompromise (8) }, under tag. Only the nine defined bits may be set; as with the key usage extension, trailing zero bits, which DER drops, are accepted.
	internal static CrlReasonFlags ReadReasons(ref DerReader reader, Asn1Tag tag)
	{
		ReadOnlySpan<byte> bits = reader.ReadBitString(tag, wholeBytes: false).Span;

		if (bits.Length > 1 && ((bits[1] & 0x7F) is not 0 || bits.Slice(2).ContainsAnyExcept((byte)0)))
		{
			throw new AsnContentException();
		}

		return (CrlReasonFlags)((bits.Length > 0 ? bits[0] : 0) | (bits.Length > 1 ? bits[1] << 8 : 0));
	}

	// DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }, with implicit tags.
	private static CrlDistributionPoint Read(ref DerReader reader)
	{
		DerReader sequence = reader.ReadSequence();
		DistributionPointName? distributionPoint = null;
		CrlReasonFlags? reasons = null;
		GeneralName[]? crlIssuer = null;

		if (sequence.PeekTagIs(DistributionPointTag))
		{
			distributionPoint = DistributionPointName.Read(ref sequence, DistributionPointTag);
		}

		if (sequence.PeekTagIs(ReasonsTag))
		{
			reasons = ReadReasons(ref sequence, ReasonsTag);
		}

		if (sequence.PeekTagIs(CrlIssuerTag))
		{
			crlIssuer = GeneralName.ReadGeneralNames(ref sequence, CrlIssuerTag);
		}

		sequence.ThrowIfNotEmpty();

		if (distributionPoint is null && crlIssuer is null)
		{
			throw new AsnContentException("A distribution point has neither a distributionPoint nor a cRLIssuer.");
		}

		return new CrlDistributionPoint(distributionPoint, reasons, crlIssuer);
	}
}
