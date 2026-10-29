using System.Globalization;

namespace CryptoBase.X509;

/// <summary>
/// Validates certificate chains with the platform's <see cref="X509Chain" />.
/// </summary>
/// <remarks>
/// <para>
/// The platform builds the chain from the peer's first certificate, with the others as extra certificates, under a copy of the policy to whose <see cref="X509ChainPolicy.ApplicationPolicy" /> the extended key usage of <see cref="CertificateValidationContext.Usage" /> is added.
/// The <see cref="X509ChainPolicy.VerificationFlags" /> of the policy apply to every check of the platform, that extended key usage included: <see cref="X509VerificationFlags.IgnoreWrongUsage" />, for example, accepts a certificate without it.
/// A host name, with any trailing dot removed and a DNS name converted to its ASCII form, must match a DNS name, with wildcards allowed, or an IP address in the subject alternative name extension; as RFC 9525 requires, the common name of the subject is not used.
/// The validator checks the host name itself, so no flag skips that check.
/// </para>
/// <para>
/// The platform also verifies the signatures, so a chain with an algorithm that the platform does not support, such as ML-DSA on an older system, fails validation.
/// The validator does not check <see cref="Certificate.KeyUsage" />.
/// A certificate that the platform does not load gives <see cref="CertificateValidationError.UnsupportedAlgorithm" />; chain status gives, in this order, <see cref="CertificateValidationError.InvalidSignature" />, <see cref="CertificateValidationError.Expired" />, <see cref="CertificateValidationError.Revoked" />, <see cref="CertificateValidationError.UntrustedRoot" /> (including a partial chain), <see cref="CertificateValidationError.NotValidForUsage" />, <see cref="CertificateValidationError.RevocationUnknown" /> (including offline revocation) or <see cref="CertificateValidationError.Unspecified" />.
/// </para>
/// <para>
/// Validation completes synchronously unless the policy checks revocation online or allows certificate downloads, in which case it runs on the thread pool, and <see cref="X509ChainPolicy.UrlRetrievalTimeout" /> bounds each retrieval.
/// Cancellation is observed until the platform starts building the chain. The platform cannot stop a build that has started, so the returned task then completes when the build ends, and no work for the call is left running afterwards.
/// The validator holds its own copies of the certificates in the stores of its policy, so the caller may dispose them after construction.
/// </para>
/// </remarks>
public sealed class PlatformCertificateValidator : ICertificateValidator
{
	// id-kp-serverAuth and id-kp-clientAuth, made once with the constructor that skips the friendly-name lookup of Oid(string).
	private static readonly Oid ServerAuthenticationUsage = new("1.3.6.1.5.5.7.3.1", null);
	private static readonly Oid ClientAuthenticationUsage = new("1.3.6.1.5.5.7.3.2", null);

	private static readonly (X509ChainStatusFlags Flags, CertificateValidationError Error)[] ChainErrors =
	[
		(X509ChainStatusFlags.NotSignatureValid, CertificateValidationError.InvalidSignature),
		(X509ChainStatusFlags.NotTimeValid, CertificateValidationError.Expired),
		(X509ChainStatusFlags.Revoked, CertificateValidationError.Revoked),
		(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain, CertificateValidationError.UntrustedRoot),
		(X509ChainStatusFlags.NotValidForUsage, CertificateValidationError.NotValidForUsage),
		(X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation, CertificateValidationError.RevocationUnknown),
	];

	private readonly X509ChainPolicy _policy;

	/// <summary>
	/// Initializes a validator.
	/// </summary>
	/// <param name="policy">The chain policy, which the validator copies with its certificates; <see langword="null" /> for the system's trusted roots without revocation checks or certificate downloads.</param>
	public PlatformCertificateValidator(X509ChainPolicy? policy = null)
	{
		if (policy is null)
		{
			_policy = new X509ChainPolicy
			{
				RevocationMode = X509RevocationMode.NoCheck,
				DisableCertificateDownloads = true
			};
			return;
		}

		// Clone shares the certificates, which are replaced with copies; it also shares the Oid instances, whose values cannot change.
		_policy = policy.Clone();
		CopyCertificates(_policy.CustomTrustStore);
		CopyCertificates(_policy.ExtraStore);
	}

	/// <inheritdoc />
	public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(context);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
		}

		X509ChainPolicy policy = _policy.Clone();

		if (policy.RevocationMode is X509RevocationMode.Online || !policy.DisableCertificateDownloads)
		{
			return new ValueTask<CertificateValidationResult>(Task.Run(() => Validate(context, policy), cancellationToken));
		}

		return ValueTask.FromResult(Validate(context, policy));
	}

	// The copies belong to the validator, and every call uses them, so they are released with it rather than disposed.
	private static void CopyCertificates(X509Certificate2Collection certificates)
	{
		for (int i = 0; i < certificates.Count; ++i)
		{
			certificates[i] = X509CertificateLoader.LoadCertificate(certificates[i].RawDataMemory.Span);
		}
	}

	private static CertificateValidationResult Validate(CertificateValidationContext context, X509ChainPolicy policy)
	{
		List<X509Certificate2> certificates = new(context.PresentedCertificates.Count);

		try
		{
			foreach (Certificate certificate in context.PresentedCertificates)
			{
				try
				{
					certificates.Add(X509CertificateLoader.LoadCertificate(certificate.Encoded.Span));
				}
				catch (CryptographicException e)
				{
					return CertificateValidationResult.Invalid(CertificateValidationError.UnsupportedAlgorithm, e.Message);
				}
			}

			for (int i = 1; i < certificates.Count; ++i)
			{
				policy.ExtraStore.Add(certificates[i]);
			}

			policy.ApplicationPolicy.Add(context.Usage is CertificateUsage.ServerAuthentication ? ServerAuthenticationUsage : ClientAuthenticationUsage);
			return Build(certificates[0], policy, context.HostName);
		}
		finally
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				certificate.Dispose();
			}
		}
	}

	private static CertificateValidationResult Build(X509Certificate2 leaf, X509ChainPolicy policy, string? hostName)
	{
		using X509Chain chain = new();
		chain.ChainPolicy = policy;

		try
		{
			if (!chain.Build(leaf))
			{
				return FromChainStatus(chain.ChainStatus);
			}

			return hostName is null ? CertificateValidationResult.Valid : MatchHostName(leaf, hostName);
		}
		catch (CryptographicException e)
		{
			return CertificateValidationResult.Invalid(CertificateValidationError.Unspecified, e.Message);
		}
		finally
		{
			foreach (X509ChainElement element in chain.ChainElements)
			{
				element.Certificate.Dispose();
			}
		}
	}

	private static CertificateValidationResult FromChainStatus(X509ChainStatus[] statuses)
	{
		X509ChainStatusFlags flags = X509ChainStatusFlags.NoError;

		foreach (X509ChainStatus status in statuses)
		{
			flags |= status.Status;
		}

		string message = string.Join(" ", statuses.Select(static status => status.StatusInformation.Trim()).Where(static information => information.Length > 0).Distinct());

		foreach ((X509ChainStatusFlags candidate, CertificateValidationError error) in ChainErrors)
		{
			if ((flags & candidate) is not X509ChainStatusFlags.NoError)
			{
				return CertificateValidationResult.Invalid(error, message);
			}
		}

		return CertificateValidationResult.Invalid(CertificateValidationError.Unspecified, message);
	}

	private static CertificateValidationResult MatchHostName(X509Certificate2 certificate, string hostName)
	{
		try
		{
			string trimmed = hostName.TrimEnd('.');
			string normalized = Uri.CheckHostName(trimmed) is UriHostNameType.IPv4 or UriHostNameType.IPv6 ? trimmed : new IdnMapping().GetAscii(trimmed);

			return certificate.MatchesHostname(normalized, allowWildcards: true, allowCommonName: false)
				? CertificateValidationResult.Valid
				: CertificateValidationResult.Invalid(CertificateValidationError.NameMismatch, $"The certificate does not identify {hostName}.");
		}
		catch (ArgumentException e)
		{
			// The host name is not a DNS name or an IP address.
			return CertificateValidationResult.Invalid(CertificateValidationError.NameMismatch, e.Message);
		}
		catch (CryptographicException e)
		{
			// The subject alternative name extension is repeated or does not decode.
			return CertificateValidationResult.Invalid(CertificateValidationError.Malformed, e.Message);
		}
	}
}
