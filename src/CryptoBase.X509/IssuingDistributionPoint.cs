namespace CryptoBase.X509;

/// <summary>
/// Represents the value of an issuing distribution point extension (RFC 5280, Sec. 5.2.5), which states the scope of a CRL.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class IssuingDistributionPoint
{
	private static readonly Asn1Tag DistributionPointTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag OnlyContainsUserCertsTag = new(TagClass.ContextSpecific, 1);
	private static readonly Asn1Tag OnlyContainsCACertsTag = new(TagClass.ContextSpecific, 2);
	private static readonly Asn1Tag OnlySomeReasonsTag = new(TagClass.ContextSpecific, 3);
	private static readonly Asn1Tag IndirectCrlTag = new(TagClass.ContextSpecific, 4);
	private static readonly Asn1Tag OnlyContainsAttributeCertsTag = new(TagClass.ContextSpecific, 5);

	private IssuingDistributionPoint(DistributionPointName? distributionPoint, bool onlyContainsUserCertificates, bool onlyContainsCACertificates, CrlReasonFlags? onlySomeReasons, bool indirectCrl, bool onlyContainsAttributeCertificates)
	{
		DistributionPoint = distributionPoint;
		OnlyContainsUserCertificates = onlyContainsUserCertificates;
		OnlyContainsCACertificates = onlyContainsCACertificates;
		OnlySomeReasons = onlySomeReasons;
		IndirectCrl = indirectCrl;
		OnlyContainsAttributeCertificates = onlyContainsAttributeCertificates;
	}

	/// <summary>
	/// Gets the distributionPoint field, or <see langword="null" /> if it is absent.
	/// </summary>
	public DistributionPointName? DistributionPoint { get; }

	/// <summary>
	/// Gets a value that indicates whether the CRL covers only end entity certificates.
	/// </summary>
	public bool OnlyContainsUserCertificates { get; }

	/// <summary>
	/// Gets a value that indicates whether the CRL covers only CA certificates.
	/// </summary>
	public bool OnlyContainsCACertificates { get; }

	/// <summary>
	/// Gets the onlySomeReasons field, or <see langword="null" /> if it is absent, which covers every reason.
	/// </summary>
	public CrlReasonFlags? OnlySomeReasons { get; }

	/// <summary>
	/// Gets a value that indicates whether the CRL covers certificates that another authority issued.
	/// </summary>
	public bool IndirectCrl { get; }

	/// <summary>
	/// Gets a value that indicates whether the CRL covers only attribute certificates.
	/// </summary>
	public bool OnlyContainsAttributeCertificates { get; }

	// IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, onlyContainsUserCerts [1] BOOLEAN DEFAULT FALSE, onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE, onlySomeReasons [3] ReasonFlags OPTIONAL, indirectCRL [4] BOOLEAN DEFAULT FALSE, onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }, with implicit tags.
	internal static IssuingDistributionPoint Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		sequence.ThrowIfEmpty();

		DistributionPointName? distributionPoint = sequence.PeekTagIs(DistributionPointTag) ? DistributionPointName.Read(ref sequence, DistributionPointTag) : null;
		bool onlyContainsUserCertificates = sequence.ReadTrueOrAbsent(OnlyContainsUserCertsTag);
		bool onlyContainsCACertificates = sequence.ReadTrueOrAbsent(OnlyContainsCACertsTag);
		CrlReasonFlags? onlySomeReasons = null;

		if (sequence.PeekTagIs(OnlySomeReasonsTag))
		{
			onlySomeReasons = CrlDistributionPoint.ReadReasons(ref sequence, OnlySomeReasonsTag);
		}

		bool indirectCrl = sequence.ReadTrueOrAbsent(IndirectCrlTag);
		bool onlyContainsAttributeCertificates = sequence.ReadTrueOrAbsent(OnlyContainsAttributeCertsTag);
		sequence.ThrowIfNotEmpty();

		if (onlyContainsUserCertificates && onlyContainsCACertificates || onlyContainsUserCertificates && onlyContainsAttributeCertificates || onlyContainsCACertificates && onlyContainsAttributeCertificates)
		{
			throw new AsnContentException("More than one of the only-contains fields is asserted.");
		}

		return new IssuingDistributionPoint(distributionPoint, onlyContainsUserCertificates, onlyContainsCACertificates, onlySomeReasons, indirectCrl, onlyContainsAttributeCertificates);
	}
}
