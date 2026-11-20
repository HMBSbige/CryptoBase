namespace CryptoBase.X509;

/// <summary>
/// Defines a check of whether the certificates that a peer presents are acceptable.
/// </summary>
/// <remarks>
/// An implementation decides trust, validity and identity however it chooses, such as by building a chain to trusted roots or by comparing a fingerprint, and reports problems with the certificates as an invalid result rather than by throwing.
/// The result holds every problem that the implementation found, and the certification path that it built or matched, if any; <see cref="CertificateValidationResult.Create" /> makes one.
/// An implementation that waits for the network observes <see cref="CertificateValidationContext.Deadline" />.
/// Implementations must allow concurrent calls on one instance.
/// A validator does not check <see cref="Certificate.KeyUsage" />; the caller checks it.
/// </remarks>
public interface ICertificateValidator
{
	/// <summary>
	/// Gets whether the validator checks <see cref="CertificateValidationContext.StapledOcspResponse" />; <see langword="false" /> by default, for a validator that ignores it.
	/// </summary>
	/// <remarks>
	/// A validator for which it is <see langword="true" /> reports a stapled response that it does not accept as <see cref="CertificateValidationError.InvalidOcspResponse" />.
	/// An implementation returns the same value for the life of the instance.
	/// </remarks>
	bool UsesStapledOcspResponse => false;

	/// <summary>
	/// Gets the DER-encoded subject names (RFC 5280, Sec. 4.1.2.6) of the validator's trust anchors, for a caller that tells its peer which certification authorities it accepts;
	/// empty by default, for a validator that names none.
	/// </summary>
	/// <remarks>The list is immutable, and an implementation returns the same names for the life of the instance.</remarks>
	IReadOnlyList<ReadOnlyMemory<byte>> TrustAnchorSubjects => [];

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
