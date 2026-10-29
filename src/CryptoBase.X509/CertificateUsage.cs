namespace CryptoBase.X509;

/// <summary>
/// Identifies what a peer's certificate authenticates.
/// </summary>
public enum CertificateUsage
{
	/// <summary>
	/// A server to a client, the extended key usage id-kp-serverAuth.
	/// </summary>
	ServerAuthentication = 1,

	/// <summary>
	/// A client to a server, the extended key usage id-kp-clientAuth.
	/// </summary>
	ClientAuthentication = 2
}
