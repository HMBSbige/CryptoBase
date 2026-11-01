namespace CryptoBase.X509;

/// <summary>
/// Validates the peer's certificate by its fingerprint (RFC 8122, Sec. 5), as a WebRTC peer does with the fingerprints that the other sent in SDP (RFC 8842, Sec. 5.1).
/// </summary>
/// <remarks>
/// <para>
/// As RFC 8122, Sec. 5.1 requires, the validator selects the fingerprints of its most preferred hash function out of those given, SHA-512, then SHA-384, SHA-256 and SHA-1, and accepts the peer's first certificate if the digest of its DER encoding with that function equals one of them, such as one for each certificate that the peer may use.
/// It does not consult the fingerprints of the other hash functions, so that a fingerprint with a weaker hash function cannot stand in for one with a stronger function that does not match.
/// It ignores the fingerprints with MD5 and MD2, with which RFC 8122, Sec. 5 forbids verifying, and with SHA-224 or any other hash function; if none is left, validation gives <see cref="CertificateValidationError.UnsupportedAlgorithm" />.
/// </para>
/// <para>
/// Only the digest is compared: the validity period, the extensions and the signature of the certificate, the other certificates that the peer presented, <see cref="CertificateValidationContext.Usage" /> and <see cref="CertificateValidationContext.HostName" /> are not checked, as the fingerprint, from a signaling channel that the caller trusts, binds the certificate to the peer.
/// A certificate that matches no fingerprint gives <see cref="CertificateValidationError.UntrustedRoot" />, with no path; one that matches gives a path of the certificate alone, which ends at a trust anchor, as the fingerprint vouches for its public key and not its signature.
/// </para>
/// <para>
/// Validation completes synchronously and uses no network. Instances are immutable, so they may be used concurrently.
/// </para>
/// </remarks>
public sealed class FingerprintCertificateValidator : ICertificateValidator
{
	private const int MaxDigestLength = 64;

	// The hash functions from the most preferred: the strongest first.
	private static readonly HashAlgorithmName[] Preference = [HashAlgorithmName.SHA512, HashAlgorithmName.SHA384, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1];

	private readonly HashAlgorithmName _hashAlgorithm;
	private readonly byte[][] _digests;

	/// <summary>
	/// Initializes a validator.
	/// </summary>
	/// <param name="fingerprints">The fingerprints that the peer sent, of any hash functions; the validator keeps those that it uses.</param>
	/// <exception cref="ArgumentNullException"><paramref name="fingerprints" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="fingerprints" /> is empty or holds <see langword="null" />.</exception>
	public FingerprintCertificateValidator(IEnumerable<CertificateFingerprint> fingerprints)
	{
		ArgumentNullException.ThrowIfNull(fingerprints);

		CertificateFingerprint[] copy = [.. fingerprints];

		if (copy.Length is 0 || Array.IndexOf(copy, null) >= 0)
		{
			throw new ArgumentException("The fingerprints must include at least one fingerprint and no null.", nameof(fingerprints));
		}

		_digests = [];

		foreach (HashAlgorithmName candidate in Preference)
		{
			byte[][] digests = [.. copy.Where(fingerprint => fingerprint.HashAlgorithm == candidate).Select(static fingerprint => fingerprint.Digest.ToArray())];

			if (digests.Length > 0)
			{
				_hashAlgorithm = candidate;
				_digests = digests;
				break;
			}
		}
	}

	/// <inheritdoc />
	public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(context);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
		}

		if (_digests.Length is 0)
		{
			return ValueTask.FromResult(CertificateValidationResult.Invalid(CertificateValidationError.UnsupportedAlgorithm, "No fingerprint uses SHA-512, SHA-384, SHA-256 or SHA-1."));
		}

		Certificate certificate = context.PresentedCertificates[0];
		Span<byte> digest = stackalloc byte[MaxDigestLength];
		digest = digest.Slice(0, CryptographicOperations.HashData(_hashAlgorithm, certificate.Encoded.Span, digest));

		foreach (byte[] expected in _digests)
		{
			if (digest.SequenceEqual(expected))
			{
				return ValueTask.FromResult(CertificateValidationResult.Create([], [certificate], CertificatePathEnd.TrustAnchor));
			}
		}

		return ValueTask.FromResult(CertificateValidationResult.Invalid(CertificateValidationError.UntrustedRoot, $"The certificate matches no {CertificateFingerprint.TextualName(_hashAlgorithm)} fingerprint."));
	}
}
