namespace CryptoBase.X509;

/// <summary>
/// Describes the certificates that a peer presented and what they are for.
/// </summary>
public sealed class CertificateValidationContext
{
	/// <summary>
	/// Initializes a context.
	/// </summary>
	/// <param name="presentedCertificates">The certificates as the peer presented them, its own first; the context holds a copy of the list.</param>
	/// <param name="usage">What the certificate authenticates.</param>
	/// <exception cref="ArgumentNullException"><paramref name="presentedCertificates" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="presentedCertificates" /> is empty or holds <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="usage" /> is not defined.</exception>
	public CertificateValidationContext(IReadOnlyList<Certificate> presentedCertificates, CertificateUsage usage)
	{
		ArgumentNullException.ThrowIfNull(presentedCertificates);

		Certificate[] copy = [.. presentedCertificates];

		if (copy.Length is 0 || Array.IndexOf(copy, null) >= 0)
		{
			throw new ArgumentException("The presented certificates must include at least one certificate and no null.", nameof(presentedCertificates));
		}

		if (usage is not (CertificateUsage.ServerAuthentication or CertificateUsage.ClientAuthentication))
		{
			throw new ArgumentOutOfRangeException(nameof(usage), usage, "The usage is not defined.");
		}

		PresentedCertificates = Array.AsReadOnly(copy);
		Usage = usage;
	}

	/// <summary>
	/// Gets the certificates as the peer presented them, its own first.
	/// </summary>
	/// <remarks>The others may be in any order and include certificates that the path does not need.</remarks>
	public IReadOnlyList<Certificate> PresentedCertificates { get; }

	/// <summary>
	/// Gets what the certificate authenticates.
	/// </summary>
	public CertificateUsage Usage { get; }

	/// <summary>
	/// Gets the DNS name or IP address that the certificate must identify, or <see langword="null" /> for the validator to check no identity.
	/// </summary>
	/// <remarks><see langword="null" /> does not authenticate the peer: a result that accepts the certificates then says nothing about whom the peer's certificate identifies, so the caller must bind the identity another way, such as a server that authorizes the client's certificate itself or an expected digest from a trusted source.</remarks>
	public string? HostName { get; init; }
}
