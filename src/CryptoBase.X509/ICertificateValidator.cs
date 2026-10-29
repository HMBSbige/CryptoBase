namespace CryptoBase.X509;

/// <summary>
/// Defines a check of whether the certificates that a peer presents are acceptable.
/// </summary>
/// <remarks>
/// An implementation decides trust, validity and identity however it chooses, such as by building a chain to trusted roots or by comparing a fingerprint, and reports problems with the certificates as an invalid result rather than by throwing.
/// Implementations must allow concurrent calls on one instance.
/// A validator does not check <see cref="Certificate.KeyUsage" />; the caller checks it.
/// </remarks>
public interface ICertificateValidator
{
	/// <summary>
	/// Validates the certificates that a peer presented.
	/// </summary>
	/// <remarks>An implementation may observe <paramref name="cancellationToken" /> only at some stages of its work; a caller with a deadline enforces it itself.</remarks>
	/// <param name="context">The certificates and what they are for.</param>
	/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
	/// <returns>The result.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="context" /> is <see langword="null" />.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default);
}
