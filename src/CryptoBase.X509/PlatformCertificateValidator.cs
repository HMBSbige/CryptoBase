namespace CryptoBase.X509;

/// <summary>
/// Validates certificate chains with the platform's <see cref="X509Chain" />.
/// </summary>
/// <remarks>
/// <para>
/// The platform builds the chain from the peer's first certificate, with the others as extra certificates, under a copy of the policy to whose <see cref="X509ChainPolicy.ApplicationPolicy" /> the extended key usage of <see cref="CertificateValidationContext.Usage" /> is added unless it is there already.
/// The <see cref="X509ChainPolicy.VerificationFlags" /> of the policy apply to every check of the platform, that extended key usage included: <see cref="X509VerificationFlags.IgnoreWrongUsage" />, for example, accepts a certificate without it.
/// A host name must be one that the subject alternative name extension identifies, as <see cref="Certificate.MatchHostName" /> specifies, so that every platform matches names alike; as RFC 9525 requires, the common name of the subject is not used.
/// The validator checks the host name itself, whether or not the chain is valid, so no flag skips that check. Otherwise the platform alone decides whether the chain is acceptable.
/// </para>
/// <para>
/// The platform also verifies the signatures, so a chain with an algorithm that the platform does not support, such as ML-DSA on an older system, fails validation.
/// The platforms do not verify SM2 signatures with the default ID of GB/T 35276-2017, so SM2 chains fail validation; <see cref="TrustAnchorCertificateValidator" /> validates them.
/// The validator does not check <see cref="Certificate.KeyUsage" />.
/// </para>
/// <para>
/// The result accepts the certificates when the platform accepts the chain and nothing below rejects them, and otherwise holds every error that applies:
/// <see cref="CertificateValidationError.UnsupportedAlgorithm" /> for a certificate that the platform does not load, which ends validation, or for a chain that the platform fails to build, such as one with a DSA signature on Windows;
/// for each status of a chain that the platform does not accept, <see cref="CertificateValidationError.InvalidSignature" />, <see cref="CertificateValidationError.Expired" />, <see cref="CertificateValidationError.Revoked" />, <see cref="CertificateValidationError.UntrustedRoot" /> (including a partial chain), <see cref="CertificateValidationError.NotValidForUsage" /> (including an issuance policy that the chain does not meet), <see cref="CertificateValidationError.RevocationUnknown" /> (including offline revocation) or <see cref="CertificateValidationError.Unspecified" />, leaving out the statuses that <see cref="X509ChainPolicy.VerificationFlags" /> ignores;
/// <see cref="CertificateValidationError.Malformed" /> for a subject alternative name extension that does not decode when a host name is given;
/// and <see cref="CertificateValidationError.NameMismatch" /> for a host name that the certificate does not identify, or that is neither a DNS name nor an IP address.
/// </para>
/// <para>
/// On every platform, the flags leave out these statuses: <see cref="X509VerificationFlags.IgnoreNotTimeValid" /> NotTimeValid of any certificate; <see cref="X509VerificationFlags.AllowUnknownCertificateAuthority" /> UntrustedRoot and PartialChain; <see cref="X509VerificationFlags.IgnoreWrongUsage" /> NotValidForUsage; <see cref="X509VerificationFlags.IgnoreInvalidBasicConstraints" /> InvalidBasicConstraints; <see cref="X509VerificationFlags.IgnoreInvalidName" /> InvalidNameConstraints, HasNotSupportedNameConstraint, HasNotDefinedNameConstraint, HasNotPermittedNameConstraint and HasExcludedNameConstraint; <see cref="X509VerificationFlags.IgnoreInvalidPolicy" /> NoIssuanceChainPolicy; and RevocationStatusUnknown and OfflineRevocation, per certificate, <see cref="X509VerificationFlags.IgnoreEndRevocationUnknown" /> of the peer's, <see cref="X509VerificationFlags.IgnoreRootRevocationUnknown" /> of a root and <see cref="X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown" /> of the others.
/// Each platform decides which certificates are roots: Windows the last certificate of a complete path, and Linux and macOS every certificate after the peer's whose issuer is its subject, such as one that rolls over a CA key.
/// The platforms do not report the same statuses for every chain: Windows reports a certificate policy that the chain does not meet as NoIssuanceChainPolicy where Linux and macOS report NotValidForUsage, macOS reports a signature that does not verify as a partial chain, Linux reports a leaf whose subject alternative name extension does not decode as a partial chain, Windows and Linux report a name constraint of a form that they do not support, such as registeredID, as HasNotSupportedNameConstraint for a certificate with a name of that form where macOS reports InvalidNameConstraints for an intermediate CA with such a constraint, whatever names the certificates below it have, and the platforms check the revocation of different certificates.
/// </para>
/// <para>
/// <see cref="CertificateValidationResult.Path" /> is the path that the platform built, whether or not it is valid, with the certificates of the context where they appear in it; <see cref="CertificateValidationResult.PathEnd" /> is <see cref="CertificatePathEnd.MissingIssuer" /> for a partial chain, <see cref="CertificatePathEnd.UntrustedRoot" /> for one that ends at a root that is not trusted, and <see cref="CertificatePathEnd.TrustAnchor" /> otherwise; the flags change none of these, so a partial chain that <see cref="X509VerificationFlags.AllowUnknownCertificateAuthority" /> accepts still ends at <see cref="CertificatePathEnd.MissingIssuer" />.
/// If a certificate of the platform's path does not decode as a <see cref="Certificate" />, the result has no path, and the platform's decision stands.
/// </para>
/// <para>
/// Validation runs on the thread pool when the policy checks revocation, online or offline, or allows certificate downloads, and the deadline has not passed, as macOS retrieves for an offline check too; it completes synchronously otherwise.
/// <see cref="X509ChainPolicy.UrlRetrievalTimeout" />, or 15 seconds when it is zero, bounds each retrieval, shortened to the time left until <see cref="CertificateValidationContext.Deadline" /> in whole milliseconds. On Windows and Linux the timeout applies to each retrieval in turn, so a chain that needs several retrievals can take longer than the time left; on macOS it does not apply, and the system bounds each retrieval itself.
/// Once less than a millisecond is left, the validator neither downloads certificates nor checks revocation, offline included; a policy that checks revocation then gives <see cref="CertificateValidationError.RevocationUnknown" /> unless its flags ignore an unknown status for every certificate that <see cref="X509ChainPolicy.RevocationFlag" /> covers, each by the flag that the platform applies to it as above; as on every platform, the last certificate of a complete path is not covered.
/// Cancellation is observed until the platform starts building the chain. The platform cannot stop a build that has started, so the returned task then completes when the build ends, and no work for the call is left running afterwards.
/// The validator holds its own copies of the certificates in the stores of its policy, so the caller may dispose them after construction.
/// </para>
/// </remarks>
public sealed class PlatformCertificateValidator : ICertificateValidator
{
	private const X509ChainStatusFlags RevocationUnknownStatuses = X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;

	private const X509VerificationFlags RevocationUnknownFlags = X509VerificationFlags.IgnoreEndRevocationUnknown | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown | X509VerificationFlags.IgnoreRootRevocationUnknown;

	// Every status of a name constraint, which IgnoreInvalidName ignores: one that is invalid, has a form or syntax that the platform does not support or define, or excludes or does not permit a name.
	private const X509ChainStatusFlags NameConstraintStatuses = X509ChainStatusFlags.InvalidNameConstraints | X509ChainStatusFlags.HasNotSupportedNameConstraint | X509ChainStatusFlags.HasNotDefinedNameConstraint | X509ChainStatusFlags.HasNotPermittedNameConstraint | X509ChainStatusFlags.HasExcludedNameConstraint;

	// The timeout of each retrieval on Windows and Linux when X509ChainPolicy.UrlRetrievalTimeout is zero.
	private static readonly TimeSpan PlatformUrlRetrievalTimeout = TimeSpan.FromSeconds(15);

	private static readonly TimeSpan OneMillisecond = TimeSpan.FromMilliseconds(1);

	// id-kp-serverAuth and id-kp-clientAuth, made once with the constructor that skips the friendly-name lookup of Oid(string).
	private static readonly Oid ServerAuthenticationUsage = new("1.3.6.1.5.5.7.3.1", null);
	private static readonly Oid ClientAuthenticationUsage = new("1.3.6.1.5.5.7.3.2", null);

	// The statuses that each flag ignores on every platform. The revocation flags apply per certificate, by GetRevocationUnknownFlags.
	private static readonly (X509VerificationFlags Flag, X509ChainStatusFlags Statuses)[] IgnoredStatuses =
	[
		(X509VerificationFlags.IgnoreNotTimeValid, X509ChainStatusFlags.NotTimeValid),
		(X509VerificationFlags.IgnoreInvalidBasicConstraints, X509ChainStatusFlags.InvalidBasicConstraints),
		(X509VerificationFlags.AllowUnknownCertificateAuthority, X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain),
		(X509VerificationFlags.IgnoreWrongUsage, X509ChainStatusFlags.NotValidForUsage),
		(X509VerificationFlags.IgnoreInvalidName, NameConstraintStatuses),
		(X509VerificationFlags.IgnoreInvalidPolicy, X509ChainStatusFlags.NoIssuanceChainPolicy),
	];

	// Any other status is Unspecified. Windows reports NoIssuanceChainPolicy where Linux and macOS report NotValidForUsage.
	private static readonly (X509ChainStatusFlags Statuses, CertificateValidationError Error)[] ChainErrors =
	[
		(X509ChainStatusFlags.NotSignatureValid, CertificateValidationError.InvalidSignature),
		(X509ChainStatusFlags.NotTimeValid, CertificateValidationError.Expired),
		(X509ChainStatusFlags.Revoked, CertificateValidationError.Revoked),
		(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain, CertificateValidationError.UntrustedRoot),
		(X509ChainStatusFlags.NotValidForUsage | X509ChainStatusFlags.NoIssuanceChainPolicy, CertificateValidationError.NotValidForUsage),
		(RevocationUnknownStatuses, CertificateValidationError.RevocationUnknown),
	];

	private readonly X509ChainPolicy _policy;

	/// <summary>
	/// Initializes a validator.
	/// </summary>
	/// <param name="policy">The chain policy, which the validator copies with its certificates; <see langword="null" /> for the system's trusted roots without revocation checks, downloading missing certificates.</param>
	public PlatformCertificateValidator(X509ChainPolicy? policy = null)
	{
		if (policy is null)
		{
			_policy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck };
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
		bool retrieves = policy.RevocationMode is not X509RevocationMode.NoCheck || !policy.DisableCertificateDownloads;

		if (retrieves && RetrievalLimit(context.Deadline, context.TimeProvider.GetUtcNow()) != TimeSpan.Zero)
		{
			return new ValueTask<CertificateValidationResult>(Task.Run(() => Validate(context, policy, cancellationToken), cancellationToken));
		}

		try
		{
			return ValueTask.FromResult(Validate(context, policy, cancellationToken));
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<CertificateValidationResult>(cancellationToken);
		}
	}

	// The time left until the deadline in the whole milliseconds that the platforms take, for no zero to mean their default: null without a deadline, and zero once less than a millisecond is left.
	internal static TimeSpan? RetrievalLimit(DateTimeOffset? deadline, DateTimeOffset now)
	{
		if (deadline is not { } end)
		{
			return null;
		}

		long milliseconds = (end - now).Ticks / TimeSpan.TicksPerMillisecond;
		return milliseconds > 0 ? TimeSpan.FromMilliseconds(milliseconds) : TimeSpan.Zero;
	}

	// Shortens each retrieval to the limit, or stops all of them once it is zero; returns whether the policy checked revocation, which then goes unchecked. Offline checks retrieve on macOS, so revocation is not checked at all.
	internal static bool ApplyRetrievalLimit(X509ChainPolicy policy, TimeSpan? limit)
	{
		if (limit is not { } left)
		{
			return false;
		}

		if (left > TimeSpan.Zero)
		{
			// Zero means the platform's default; Windows takes whole milliseconds, so a timeout below one would mean the default there too, and becomes one.
			TimeSpan timeout = policy.UrlRetrievalTimeout <= TimeSpan.Zero ? PlatformUrlRetrievalTimeout
				: policy.UrlRetrievalTimeout < OneMillisecond ? OneMillisecond
				: policy.UrlRetrievalTimeout;

			if (left < timeout)
			{
				policy.UrlRetrievalTimeout = left;
			}
			else if (policy.UrlRetrievalTimeout > TimeSpan.Zero)
			{
				policy.UrlRetrievalTimeout = timeout;
			}
			return false;
		}

		bool checksRevocation = policy.RevocationMode is not X509RevocationMode.NoCheck;
		policy.RevocationMode = X509RevocationMode.NoCheck;
		policy.DisableCertificateDownloads = true;
		return checksRevocation;
	}

	// The flag that ignores an unknown revocation status of each certificate of the path, by the rule of the platform: the peer's certificate is the end certificate; the root is, on Windows, the last certificate of a complete path, and elsewhere every certificate whose issuer is its subject, such as one that rolls over a CA key; the others are certificate authorities.
	internal static X509VerificationFlags[] GetRevocationUnknownFlags(ReadOnlySpan<bool> selfIssued, bool complete, bool windows)
	{
		X509VerificationFlags[] revocationFlags = new X509VerificationFlags[selfIssued.Length];

		for (int i = 0; i < revocationFlags.Length; ++i)
		{
			bool root = windows ? complete && i == revocationFlags.Length - 1 : selfIssued[i];

			revocationFlags[i] = i is 0 ? X509VerificationFlags.IgnoreEndRevocationUnknown
				: root ? X509VerificationFlags.IgnoreRootRevocationUnknown
				: X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
		}

		return revocationFlags;
	}

	// The statuses that fail the chain: those that the flags do not ignore. The revocation statuses of each certificate are ignored by the flag of revocationFlags at its index; one of the chain alone, which no platform reports, only by all three.
	internal static X509ChainStatusFlags ReportedStatuses(X509ChainStatusFlags chainStatus, ReadOnlySpan<X509ChainStatusFlags> elementStatus, ReadOnlySpan<X509VerificationFlags> revocationFlags, X509VerificationFlags flags)
	{
		X509ChainStatusFlags reported = chainStatus & ~RevocationUnknownStatuses;

		foreach ((X509VerificationFlags flag, X509ChainStatusFlags statuses) in IgnoredStatuses)
		{
			if ((flags & flag) is not X509VerificationFlags.NoFlag)
			{
				reported &= ~statuses;
			}
		}

		bool perCertificate = false;

		for (int i = 0; i < elementStatus.Length; ++i)
		{
			X509ChainStatusFlags revocation = elementStatus[i] & RevocationUnknownStatuses;

			if (revocation is not X509ChainStatusFlags.NoError)
			{
				perCertificate = true;

				if ((flags & revocationFlags[i]) is X509VerificationFlags.NoFlag)
				{
					reported |= revocation;
				}
			}
		}

		if (!perCertificate && (flags & RevocationUnknownFlags) != RevocationUnknownFlags)
		{
			reported |= chainStatus & RevocationUnknownStatuses;
		}

		return reported;
	}

	// Whether a revocation check that the deadline skipped leaves unknown a status that the flags do not ignore: of the peer's certificate, and of the issuers before the root unless the policy checks only the peer's, each ignored by the flag of revocationFlags at its index, which holds one flag at least. Like the platforms, it does not count the root, and takes a self-signed certificate of the peer for the peer's, not a root.
	internal static bool SkippedRevocationMatters(ReadOnlySpan<X509VerificationFlags> revocationFlags, bool complete, X509RevocationFlag revocationFlag, X509VerificationFlags flags)
	{
		int count = revocationFlag is X509RevocationFlag.EndCertificateOnly ? 1
			: complete ? Math.Max(revocationFlags.Length - 1, 1)
			: revocationFlags.Length;

		foreach (X509VerificationFlags revocationUnknownFlag in revocationFlags.Slice(0, count))
		{
			if ((flags & revocationUnknownFlag) is X509VerificationFlags.NoFlag)
			{
				return true;
			}
		}

		return false;
	}

	internal static CertificatePathEnd GetPathEnd(X509ChainStatusFlags chainStatus, int count)
	{
		if (count is 0)
		{
			return CertificatePathEnd.None;
		}

		if ((chainStatus & X509ChainStatusFlags.PartialChain) is not X509ChainStatusFlags.NoError)
		{
			return CertificatePathEnd.MissingIssuer;
		}

		return (chainStatus & X509ChainStatusFlags.UntrustedRoot) is not X509ChainStatusFlags.NoError ? CertificatePathEnd.UntrustedRoot : CertificatePathEnd.TrustAnchor;
	}

	internal static void AddChainErrors(List<CertificateValidationError> errors, X509ChainStatusFlags reported)
	{
		X509ChainStatusFlags mapped = X509ChainStatusFlags.NoError;

		foreach ((X509ChainStatusFlags statuses, CertificateValidationError error) in ChainErrors)
		{
			mapped |= statuses;

			if ((reported & statuses) is not X509ChainStatusFlags.NoError)
			{
				errors.Add(error);
			}
		}

		if ((reported & ~mapped) is not X509ChainStatusFlags.NoError)
		{
			errors.Add(CertificateValidationError.Unspecified);
		}
	}

	// The copies belong to the validator, and every call uses them, so they are released with it rather than disposed.
	private static void CopyCertificates(X509Certificate2Collection certificates)
	{
		for (int i = 0; i < certificates.Count; ++i)
		{
			certificates[i] = X509CertificateLoader.LoadCertificate(certificates[i].RawDataMemory.Span);
		}
	}

	private static CertificateValidationResult Validate(CertificateValidationContext context, X509ChainPolicy policy, CancellationToken cancellationToken)
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

			Oid usage = context.Usage is CertificateUsage.ServerAuthentication ? ServerAuthenticationUsage : ClientAuthenticationUsage;

			if (!Contains(policy.ApplicationPolicy, usage))
			{
				policy.ApplicationPolicy.Add(usage);
			}

			// The time left is read last, as the call may have waited for the thread pool.
			bool revocationSkipped = ApplyRetrievalLimit(policy, RetrievalLimit(context.Deadline, context.TimeProvider.GetUtcNow()));
			return Build(context, certificates[0], policy, revocationSkipped, cancellationToken);
		}
		finally
		{
			foreach (X509Certificate2 certificate in certificates)
			{
				certificate.Dispose();
			}
		}
	}

	// Windows rejects a chain for a usage that the policy lists twice.
	private static bool Contains(OidCollection oids, Oid oid)
	{
		foreach (Oid other in oids)
		{
			if (other.Value == oid.Value)
			{
				return true;
			}
		}

		return false;
	}

	private static CertificateValidationResult Build(CertificateValidationContext context, X509Certificate2 leaf, X509ChainPolicy policy, bool revocationSkipped, CancellationToken cancellationToken)
	{
		using X509Chain chain = new();
		chain.ChainPolicy = policy;
		List<CertificateValidationError> errors = [];
		List<string> messages = [];

		try
		{
			bool built;

			// The last moment to observe cancellation, as the platform cannot stop a build that has started.
			cancellationToken.ThrowIfCancellationRequested();

			try
			{
				built = chain.Build(leaf);
			}
			catch (CryptographicException e)
			{
				// Windows throws, with no chain, for a signature algorithm that it does not support, such as DSA.
				built = false;
				errors.Add(CertificateValidationError.UnsupportedAlgorithm);
				messages.Add(e.Message);
			}

			X509ChainElementCollection elements = chain.ChainElements;
			X509ChainStatusFlags chainStatus = Combine(chain.ChainStatus);
			X509ChainStatusFlags[] elementStatus = new X509ChainStatusFlags[elements.Count];

			// Without a path, the peer's certificate stands alone.
			bool[] selfIssued = new bool[Math.Max(elements.Count, 1)];

			for (int i = 0; i < elementStatus.Length; ++i)
			{
				X509Certificate2 certificate = elements[i].Certificate;
				elementStatus[i] = Combine(elements[i].ChainElementStatus);
				selfIssued[i] = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
			}

			CertificatePathEnd pathEnd = GetPathEnd(chainStatus, elements.Count);
			bool complete = pathEnd is not CertificatePathEnd.MissingIssuer;
			X509VerificationFlags[] revocationFlags = GetRevocationUnknownFlags(selfIssued, complete, OperatingSystem.IsWindows());

			if (!built)
			{
				X509ChainStatusFlags reported = ReportedStatuses(chainStatus, elementStatus, revocationFlags, policy.VerificationFlags);
				AddChainErrors(errors, reported);

				if (errors.Count is 0)
				{
					errors.Add(CertificateValidationError.Unspecified);
				}

				foreach (X509ChainStatus status in chain.ChainStatus)
				{
					if ((status.Status & reported) is not X509ChainStatusFlags.NoError)
					{
						messages.Add(status.StatusInformation.Trim());
					}
				}
			}

			if (revocationSkipped && SkippedRevocationMatters(revocationFlags, complete, policy.RevocationFlag, policy.VerificationFlags))
			{
				errors.Add(CertificateValidationError.RevocationUnknown);
				messages.Add("The deadline passed before revocation was checked.");
			}

			Certificate[]? path = GetPath(context.PresentedCertificates, elements);

			if (path is null)
			{
				messages.Add("A certificate of the platform's path does not decode, so the result has no path.");
				path = [];
				pathEnd = CertificatePathEnd.None;
			}

			CheckNames(context.PresentedCertificates[0], context.HostName, errors, messages);
			string message = string.Join(" ", messages.Where(static information => information.Length > 0).Distinct());
			return CertificateValidationResult.Create(errors, path, pathEnd, message.Length > 0 ? message : null);
		}
		finally
		{
			foreach (X509ChainElement element in chain.ChainElements)
			{
				element.Certificate.Dispose();
			}
		}
	}

	private static X509ChainStatusFlags Combine(X509ChainStatus[] statuses)
	{
		X509ChainStatusFlags flags = X509ChainStatusFlags.NoError;

		foreach (X509ChainStatus status in statuses)
		{
			flags |= status.Status;
		}

		return flags;
	}

	// The platform's path, with the certificates of the context where they appear; null if a certificate does not decode.
	private static Certificate[]? GetPath(IReadOnlyList<Certificate> presented, X509ChainElementCollection elements)
	{
		Certificate[] path = new Certificate[elements.Count];

		for (int i = 0; i < path.Length; ++i)
		{
			ReadOnlySpan<byte> encoded = elements[i].Certificate.RawDataMemory.Span;
			Certificate? certificate = null;

			foreach (Certificate candidate in presented)
			{
				if (candidate.Encoded.Span.SequenceEqual(encoded))
				{
					certificate = candidate;
					break;
				}
			}

			try
			{
				path[i] = certificate ?? Certificate.Decode(encoded);
			}
			catch (ArgumentException)
			{
				return null;
			}
		}

		return path;
	}

	// The host name of the context, matched by the package rather than the platform, so that every platform matches names alike; without one, the names are not read, and the platform alone judges the extension.
	private static void CheckNames(Certificate leaf, string? hostName, List<CertificateValidationError> errors, List<string> messages)
	{
		if (hostName is null)
		{
			return;
		}

		HostNameMatch match;

		try
		{
			match = leaf.MatchHostName(hostName);
		}
		catch (ArgumentException e)
		{
			// The host name is neither a DNS name nor an IP address.
			errors.Add(CertificateValidationError.NameMismatch);
			messages.Add(e.Message);
			return;
		}

		if (match is HostNameMatch.Mismatch)
		{
			errors.Add(CertificateValidationError.NameMismatch);
			messages.Add($"The certificate does not identify {hostName}.");
		}
		else if (match is HostNameMatch.MalformedExtension)
		{
			errors.Add(CertificateValidationError.Malformed);
			messages.Add("The subject alternative name extension does not decode.");
		}
	}
}
