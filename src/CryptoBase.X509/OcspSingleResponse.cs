namespace CryptoBase.X509;

/// <summary>
/// Represents a SingleResponse of a basic OCSP response (RFC 6960, Sec. 4.2.1): the status of one certificate and its validity interval.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public sealed class OcspSingleResponse
{
	private static readonly Asn1Tag GoodTag = new(TagClass.ContextSpecific, 0);
	private static readonly Asn1Tag RevokedTag = new(TagClass.ContextSpecific, 1, true);
	private static readonly Asn1Tag UnknownTag = new(TagClass.ContextSpecific, 2);
	private static readonly Asn1Tag RevocationReasonTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag NextUpdateTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag SingleExtensionsTag = new(TagClass.ContextSpecific, 1, true);

	private OcspSingleResponse(OcspCertificateId certificateId, OcspCertificateStatus status, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, IReadOnlyList<CertificateExtension> extensions)
	{
		CertificateId = certificateId;
		Status = status;
		ThisUpdate = thisUpdate;
		NextUpdate = nextUpdate;
		Extensions = extensions;
	}

	/// <summary>
	/// Gets the identifier of the certificate.
	/// </summary>
	public OcspCertificateId CertificateId { get; }

	/// <summary>
	/// Gets the status of the certificate.
	/// </summary>
	public OcspCertificateStatus Status { get; }

	/// <summary>
	/// Gets the most recent time at which the responder knew the status to be correct, in UTC.
	/// </summary>
	public DateTimeOffset ThisUpdate { get; }

	/// <summary>
	/// Gets the time at or before which newer information will be available, in UTC, or <see langword="null" /> if the field is absent.
	/// </summary>
	public DateTimeOffset? NextUpdate { get; }

	/// <summary>
	/// Gets the singleExtensions, in the order of the encoding; empty if there are none.
	/// </summary>
	public IReadOnlyList<CertificateExtension> Extensions { get; }

	// SingleResponse ::= SEQUENCE { certID CertID, certStatus CertStatus, thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions [1] EXPLICIT Extensions OPTIONAL }.
	internal static OcspSingleResponse Read(ref DerReader reader)
	{
		DerReader sequence = reader.ReadSequence();
		OcspCertificateId certificateId = OcspCertificateId.Read(ref sequence);
		OcspCertificateStatus status = ReadCertificateStatus(ref sequence);
		DateTimeOffset thisUpdate = X509Time.ReadGeneralizedTime(ref sequence);
		DateTimeOffset? nextUpdate = sequence.TryReadExplicit(NextUpdateTag, out DerReader time) ? X509Time.ReadGeneralizedTime(ref time) : null;
		IReadOnlyList<CertificateExtension> extensions = sequence.PeekTagIs(SingleExtensionsTag) ? CertificateExtension.ReadList(ref sequence, SingleExtensionsTag) : [];
		sequence.ThrowIfNotEmpty();
		return new OcspSingleResponse(certificateId, status, thisUpdate, nextUpdate, extensions);
	}

	// CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown [2] IMPLICIT UnknownInfo }, and RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL }.
	private static OcspCertificateStatus ReadCertificateStatus(ref DerReader reader)
	{
		if (reader.PeekTagIs(GoodTag))
		{
			reader.ReadNull(GoodTag);
			return OcspCertificateStatus.Good.Instance;
		}

		if (reader.PeekTagIs(UnknownTag))
		{
			reader.ReadNull(UnknownTag);
			return OcspCertificateStatus.Unknown.Instance;
		}

		DerReader revoked = reader.ReadSequence(RevokedTag);
		DateTimeOffset revocationTime = X509Time.ReadGeneralizedTime(ref revoked);
		X509RevocationReason? revocationReason = revoked.TryReadExplicit(RevocationReasonTag, out DerReader reason) ? CertificateRevocationList.ReadReason(reason.ReadEnumeratedBytes().Span) : null;
		revoked.ThrowIfNotEmpty();
		return new OcspCertificateStatus.Revoked(revocationTime, revocationReason);
	}
}
