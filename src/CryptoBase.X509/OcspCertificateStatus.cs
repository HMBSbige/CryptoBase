namespace CryptoBase.X509;

/// <summary>
/// Specifies the status of a certificate in an OCSP response (RFC 6960, Sec. 4.2.1).
/// </summary>
public enum OcspCertificateStatus
{
	/// <summary>
	/// The responder knows no revocation of the certificate.
	/// </summary>
	Good = 0,

	/// <summary>
	/// The certificate has been revoked, temporarily or permanently, or was never issued.
	/// </summary>
	Revoked = 1,

	/// <summary>
	/// The responder does not know about the certificate.
	/// </summary>
	Unknown = 2,
}
