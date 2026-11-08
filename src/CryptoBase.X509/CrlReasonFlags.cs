namespace CryptoBase.X509;

/// <summary>
/// Represents the ReasonFlags of RFC 5280, Sec. 4.2.1.13: the revocation reasons that a CRL distribution point or an issuing distribution point covers.
/// </summary>
/// <remarks>The bits have the positions of the BIT STRING, numbered as in <see cref="X509KeyUsageFlags" />: bits 0 through 7 are the first byte from its most significant bit, and bit 8 is the most significant bit of the second.</remarks>
[Flags]
public enum CrlReasonFlags
{
	/// <summary>
	/// No reason.
	/// </summary>
	None = 0,

	/// <summary>
	/// privilegeWithdrawn, bit 7.
	/// </summary>
	PrivilegeWithdrawn = 0x01,

	/// <summary>
	/// certificateHold, bit 6.
	/// </summary>
	CertificateHold = 0x02,

	/// <summary>
	/// cessationOfOperation, bit 5.
	/// </summary>
	CessationOfOperation = 0x04,

	/// <summary>
	/// superseded, bit 4.
	/// </summary>
	Superseded = 0x08,

	/// <summary>
	/// affiliationChanged, bit 3.
	/// </summary>
	AffiliationChanged = 0x10,

	/// <summary>
	/// cACompromise, bit 2.
	/// </summary>
	CACompromise = 0x20,

	/// <summary>
	/// keyCompromise, bit 1.
	/// </summary>
	KeyCompromise = 0x40,

	/// <summary>
	/// unused, bit 0, which names no reason.
	/// </summary>
	Unused = 0x80,

	/// <summary>
	/// aACompromise, bit 8.
	/// </summary>
	AACompromise = 0x8000,
}
