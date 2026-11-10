namespace CryptoBase.X509;

// What one validation may still retrieve, so that the URIs of the certificates cannot make it work or wait without bound. The limits are counted down here alone, and GetAsync and PostAsync are the only way that a validation retrieves, so that no retrieval goes uncounted.
// The first limit that stops the retrieval of issuers becomes Limit, which the result of a validation without a valid path reports; a revocation check that reaches one learns nothing more, so that the status is unknown instead.
internal sealed class RetrievalBudget(ICertificateDataRetriever? retriever, CertificateValidationContext context, CancellationToken cancellationToken)
{
	public const int MaxIssuerRounds = 8;
	public const int MaxRetrievals = 32;
	public const long MaxRetrievedBytes = 64L << 20;
	public const int MaxRetrievedIssuers = 32;

	// The requests that a validation prepares from the URIs of its certificates, as a certificate may name any number: each URI of the issuers that is new to the validation, each OCSP responder asked and each CRL URI looked up, whether retrieved or answered from a cache.
	// The URIs beyond the limit are left out; four times the retrievals leaves room for those that a cache answers.
	public const int MaxRequests = 4 * MaxRetrievals;

	// The limits of each retrieval; a CRL has its own, as those of large public CAs are long.
	public const int MaxCertificatesPerRetrieval = 16;
	public const int MaxCertificateLength = 1 << 16;
	public const int MaxOcspResponseLength = 1 << 16;
	public const int MaxCrlLength = 32 << 20;

	// A timer cannot be longer than about 49 days; a retrieval toward a deadline beyond this is canceled once it has waited this long, as what it would give is then worth nothing.
	private static readonly TimeSpan MaxDeadlineTimer = TimeSpan.FromDays(30);

	private int _issuerRoundsLeft = MaxIssuerRounds;
	private int _retrievedIssuersLeft = MaxRetrievedIssuers;
	private int _requestsLeft = MaxRequests;
	private int _retrievalsLeft = MaxRetrievals;
	private long _retrievedBytesLeft = MaxRetrievedBytes;

	public PathProblem? Limit { get; private set; }

	// The other schemes, such as ldap, are skipped (RFC 5280, Secs. 4.2.2.1 and 4.2.1.13).
	public static Uri? ParseHttpUri(string text)
	{
		return Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https" ? uri : null;
	}

	public bool TryStartIssuerRound()
	{
		if (_issuerRoundsLeft is 0)
		{
			Reach($"{MaxIssuerRounds} rounds of retrieving issuers");
			return false;
		}

		--_issuerRoundsLeft;
		return true;
	}

	public bool TryAddIssuer()
	{
		if (_retrievedIssuersLeft is 0)
		{
			Reach($"{MaxRetrievedIssuers} retrieved certificates");
			return false;
		}

		--_retrievedIssuersLeft;
		return true;
	}

	public bool TryPrepareIssuerRequest()
	{
		if (!TryPrepareRequest())
		{
			Reach($"{MaxRequests} requests from the URIs of the certificates");
			return false;
		}

		return true;
	}

	// For an OCSP responder or a CRL, the limit is not reported: a status that the URIs left out could have told is unknown.
	public bool TryPrepareRevocationRequest()
	{
		return TryPrepareRequest();
	}

	// Whether the retrieval of issuers may retrieve once more; GetAsync counts the retrieval.
	public bool CanRetrieveIssuers()
	{
		if (_retrievalsLeft is 0 || _retrievedBytesLeft is 0)
		{
			Reach($"{MaxRetrievals} retrievals or {MaxRetrievedBytes} bytes");
			return false;
		}

		return true;
	}

	public ValueTask<ReadOnlyMemory<byte>> GetAsync(Uri uri, int limit)
	{
		return RetrieveAsync(uri, default, null, limit);
	}

	public ValueTask<ReadOnlyMemory<byte>> PostAsync(Uri uri, ReadOnlyMemory<byte> content, string contentType, int limit)
	{
		return RetrieveAsync(uri, content, contentType, limit);
	}

	// Empty if nothing may be retrieved any more, as by the limits or the deadline, or if the retrieval fails or returns more than limit. Only the cancellation of the validation throws.
	private async ValueTask<ReadOnlyMemory<byte>> RetrieveAsync(Uri uri, ReadOnlyMemory<byte> content, string? contentType, int limit)
	{
		int maxLength = (int)Math.Min(limit, _retrievedBytesLeft);

		if (retriever is null || _retrievalsLeft is 0 || maxLength is 0)
		{
			return default;
		}

		cancellationToken.ThrowIfCancellationRequested();

		TimeSpan? left = PlatformCertificateValidator.RetrievalLimit(context.Deadline, context.TimeProvider.GetUtcNow());

		if (left == TimeSpan.Zero)
		{
			return default;
		}

		--_retrievalsLeft;

		using CancellationTokenSource? timeout = left is { } time ? new CancellationTokenSource(time <= MaxDeadlineTimer ? time : MaxDeadlineTimer, context.TimeProvider) : null;
		using CancellationTokenSource? linked = timeout is null ? null : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
		CancellationToken token = linked?.Token ?? cancellationToken;

		try
		{
			ReadOnlyMemory<byte> data = contentType is null
				? await retriever.GetAsync(uri, maxLength, token).ConfigureAwait(false)
				: await retriever.PostAsync(uri, content, contentType, maxLength, token).ConfigureAwait(false);

			if (data.Length > maxLength)
			{
				return default;
			}

			_retrievedBytesLeft -= data.Length;
			return data;
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			return default;
		}
	}

	private bool TryPrepareRequest()
	{
		if (_requestsLeft is 0)
		{
			return false;
		}

		--_requestsLeft;
		return true;
	}

	private void Reach(string limit)
	{
		Limit ??= new PathProblem(CertificateValidationError.Unspecified, $"The retrieval of issuers stopped at the limit of {limit}.");
	}
}
