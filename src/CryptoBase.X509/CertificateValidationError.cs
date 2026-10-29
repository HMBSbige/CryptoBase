namespace CryptoBase.X509;

/// <summary>
/// Identifies why the certificates that a peer presented are not acceptable.
/// </summary>
public enum CertificateValidationError
{
	/// <summary>
	/// No more specific reason applies.
	/// </summary>
	Unspecified = 0,

	/// <summary>
	/// A certificate or one of its extensions is malformed.
	/// </summary>
	Malformed = 1,

	/// <summary>
	/// A certificate uses an algorithm that the validator does not support.
	/// </summary>
	UnsupportedAlgorithm = 2,

	/// <summary>
	/// A signature in the chain is invalid.
	/// </summary>
	InvalidSignature = 3,

	/// <summary>
	/// A certificate is expired or not yet valid.
	/// </summary>
	Expired = 4,

	/// <summary>
	/// A certificate is revoked.
	/// </summary>
	Revoked = 5,

	/// <summary>
	/// The chain does not lead to a trusted root.
	/// </summary>
	UntrustedRoot = 6,

	/// <summary>
	/// A certificate is not valid for the usage.
	/// </summary>
	NotValidForUsage = 7,

	/// <summary>
	/// The certificate does not identify the host name.
	/// </summary>
	NameMismatch = 8,

	/// <summary>
	/// Whether a certificate is revoked could not be determined.
	/// </summary>
	RevocationUnknown = 9
}
