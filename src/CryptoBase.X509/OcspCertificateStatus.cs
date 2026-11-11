namespace CryptoBase.X509;

/// <summary>
/// Represents a CertStatus (RFC 6960, Sec. 4.2.1): the status of a certificate in an OCSP response, a <see cref="Good" />, a <see cref="Revoked" />, or an <see cref="Unknown" />.
/// </summary>
/// <remarks>Instances are immutable, so they may be used concurrently.</remarks>
public closed class OcspCertificateStatus
{
	/// <summary>
	/// Represents the good status: the responder knows no revocation of the certificate.
	/// </summary>
	public sealed class Good : OcspCertificateStatus
	{
		private Good()
		{
		}

		internal static Good Instance { get; } = new();
	}

	/// <summary>
	/// Represents the revoked status: the certificate has been revoked, temporarily or permanently, or was never issued.
	/// </summary>
	public sealed class Revoked : OcspCertificateStatus
	{
		internal Revoked(DateTimeOffset revocationTime, X509RevocationReason? revocationReason)
		{
			RevocationTime = revocationTime;
			RevocationReason = revocationReason;
		}

		/// <summary>
		/// Gets the time at which the certificate was revoked or placed on hold, in UTC.
		/// </summary>
		public DateTimeOffset RevocationTime { get; }

		/// <summary>
		/// Gets the reason for the revocation, or <see langword="null" /> if the response gives none.
		/// </summary>
		public X509RevocationReason? RevocationReason { get; }
	}

	/// <summary>
	/// Represents the unknown status: the responder does not know about the certificate.
	/// </summary>
	public sealed class Unknown : OcspCertificateStatus
	{
		private Unknown()
		{
		}

		internal static Unknown Instance { get; } = new();
	}
}
