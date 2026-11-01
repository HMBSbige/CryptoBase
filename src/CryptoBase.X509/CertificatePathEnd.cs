namespace CryptoBase.X509;

/// <summary>
/// Identifies where the certification path of a validation result ends.
/// </summary>
public enum CertificatePathEnd
{
	/// <summary>
	/// The result has no path.
	/// </summary>
	None = 0,

	/// <summary>
	/// The last certificate is a trust anchor (RFC 5280, Sec. 6.1.1): the validator trusts its public key without relying on the certificate's own signature.
	/// </summary>
	TrustAnchor = 1,

	/// <summary>
	/// The last certificate is self-signed, as a root's is, but not a trust anchor.
	/// </summary>
	UntrustedRoot = 2,

	/// <summary>
	/// The validator found no issuer of the last certificate, which is not a trust anchor: the path is partial, and the signature of the last certificate is not verified.
	/// </summary>
	MissingIssuer = 3
}
