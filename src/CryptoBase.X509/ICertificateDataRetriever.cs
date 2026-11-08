namespace CryptoBase.X509;

/// <summary>
/// Retrieves what <see cref="TrustAnchorCertificateValidator" /> needs from the network: the certificates of issuers, CRLs and OCSP responses.
/// </summary>
/// <remarks>
/// <para>
/// A validator calls the methods on any thread, concurrently, and each URI that it passes is an absolute http or https URI from a certificate, which may not have been validated yet.
/// </para>
/// <para>
/// A retrieval that fails returns an empty value, and the validator treats the source as unavailable. Other than <see cref="OperationCanceledException" />, an exception that a method throws escapes from <see cref="ICertificateValidator.ValidateAsync" />.
/// </para>
/// </remarks>
public interface ICertificateDataRetriever
{
	/// <summary>
	/// Retrieves a certificate, a certs-only CMS message or a CRL, or an OCSP response by the GET method of RFC 9919, Sec. 6.
	/// </summary>
	/// <param name="uri">The absolute http or https URI.</param>
	/// <param name="maxLength">The most bytes to return; the validator discards a longer value, so an implementation stops reading beyond it and fails.</param>
	/// <param name="cancellationToken">The token that cancels the retrieval, by the caller of the validator or at its deadline.</param>
	/// <returns>The body of the response, which the validator only reads and does not keep once the task completes; empty if the retrieval fails.</returns>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<ReadOnlyMemory<byte>> GetAsync(Uri uri, int maxLength, CancellationToken cancellationToken);

	/// <summary>
	/// Posts an OCSP request, as RFC 6960, Appendix A.1, describes.
	/// </summary>
	/// <param name="uri">The absolute http or https URI.</param>
	/// <param name="content">The body of the request.</param>
	/// <param name="contentType">The media type of the body, application/ocsp-request.</param>
	/// <param name="maxLength">The most bytes to return; the validator discards a longer value, so an implementation stops reading beyond it and fails.</param>
	/// <param name="cancellationToken">The token that cancels the retrieval, by the caller of the validator or at its deadline.</param>
	/// <returns>The body of the response, which the validator only reads and does not keep once the task completes; empty if the retrieval fails.</returns>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<ReadOnlyMemory<byte>> PostAsync(Uri uri, ReadOnlyMemory<byte> content, string contentType, int maxLength, CancellationToken cancellationToken);
}
