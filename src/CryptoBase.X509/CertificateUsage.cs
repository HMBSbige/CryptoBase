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

internal static class CertificateUsageExtensions
{
	extension(CertificateUsage usage)
	{
		// The KeyPurposeId that the usage needs of an extended key usage extension (RFC 5280, Sec. 4.2.1.12), as a dotted-decimal object identifier.
		public string KeyPurposeId => usage is CertificateUsage.ServerAuthentication ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2";

		public string KeyPurposeName => usage is CertificateUsage.ServerAuthentication ? "id-kp-serverAuth" : "id-kp-clientAuth";
	}
}
