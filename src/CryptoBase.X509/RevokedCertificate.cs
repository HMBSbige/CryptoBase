namespace CryptoBase.X509;

/// <summary>
/// Represents an entry of the revokedCertificates list of a CRL (RFC 5280, Sec. 5.1.2.6).
/// </summary>
/// <remarks>The default value has no members set.</remarks>
public readonly struct RevokedCertificate
{
	internal RevokedCertificate(ReadOnlyMemory<byte> serialNumber, DateTimeOffset revocationDate, X509RevocationReason? reasonCode, DateTimeOffset? invalidityDate, IReadOnlyList<CertificateExtension> extensions)
	{
		SerialNumber = serialNumber;
		RevocationDate = revocationDate;
		ReasonCode = reasonCode;
		InvalidityDate = invalidityDate;
		Extensions = extensions;
	}

	/// <summary>
	/// Gets the serial number of the revoked certificate, the big-endian two's-complement contents of its INTEGER, as those of <see cref="Certificate.SerialNumber" />.
	/// </summary>
	public ReadOnlyMemory<byte> SerialNumber { get; }

	/// <summary>
	/// Gets the date on which the CA processed the revocation, in UTC.
	/// </summary>
	public DateTimeOffset RevocationDate { get; }

	/// <summary>
	/// Gets the value of the reason code entry extension (RFC 5280, Sec. 5.3.1), or <see langword="null" /> if the entry has no such extension.
	/// </summary>
	public X509RevocationReason? ReasonCode { get; }

	/// <summary>
	/// Gets the value of the invalidity date entry extension (RFC 5280, Sec. 5.3.2), in UTC, or <see langword="null" /> if the entry has no such extension.
	/// </summary>
	public DateTimeOffset? InvalidityDate { get; }

	/// <summary>
	/// Gets the entry's extensions, in the order of the encoding; empty if there are none.
	/// </summary>
	public IReadOnlyList<CertificateExtension> Extensions { get => field ?? []; }
}
