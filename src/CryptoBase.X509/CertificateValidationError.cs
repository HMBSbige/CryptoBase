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
	/// The certificates do not lead to a trust anchor, such as a chain that ends at a root that is not trusted or that is partial, which <see cref="CertificateValidationResult.PathEnd" /> tells apart.
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
	RevocationUnknown = 9,

	/// <summary>
	/// A certificate uses a signature algorithm or a public key that the validator's policy refuses, such as a signature with MD5 or SHA-1, or an RSA key shorter than the policy's minimum.
	/// </summary>
	/// <remarks>Unlike <see cref="UnsupportedAlgorithm" />, the validator knows the algorithm and refuses it by its policy; TLS and DTLS answer such a certificate with bad_certificate (RFC 9846, Sec. 4.5.1.3).</remarks>
	WeakAlgorithm = 10
}
