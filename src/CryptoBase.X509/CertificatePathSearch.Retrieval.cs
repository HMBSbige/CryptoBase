using System.Globalization;

namespace CryptoBase.X509;

// The retrieval of missing issuers and the revocation checks of a validation.
internal sealed partial class CertificatePathSearch
{
	// Limits per validation, so that the URIs of the certificates cannot make it work or wait without bound.
	public const int MaxIssuerRounds = 8;
	public const int MaxRetrievals = 32;
	public const long MaxRetrievedBytes = 64L << 20;
	public const int MaxRetrievedIssuers = 32;
	public const int MaxCertificatesPerRetrieval = 16;
	public const int MaxRejectedEdges = 8;

	// A CRL has its own limit, as those of large public CAs are long.
	public const int MaxCertificateLength = 1 << 16;
	public const int MaxOcspResponseLength = 1 << 16;
	public const int MaxCrlLength = 32 << 20;

	// RFC 9919, Sec. 6: a request of at most this many bytes after encoding, with the scheme and server name, must use GET.
	private const int MaxOcspGetLength = 255;
	private const string OcspRequestMediaType = "application/ocsp-request";

	// Certificates at a URI change rarely, and each is checked at every use.
	private static readonly TimeSpan IssuerCacheLifetime = TimeSpan.FromHours(1);

	// A timer cannot be longer than about 49 days; a deadline beyond this needs none.
	private static readonly TimeSpan MaxDeadlineTimer = TimeSpan.FromDays(30);

	// RunAsync calls the methods of this part only with this set.
	private RetrievalState Retrieval => _retrieval ?? throw new InvalidOperationException();

	private static long EdgeOf(PathNode certificate, PathNode issuer)
	{
		return (long)certificate.Index << 32 | (uint)issuer.Index;
	}

	// Another CA can name the same URI, and what it was answered must not stand in for what the certificates of this issuer find there.
	private static string GetCacheKey(ReadOnlyMemory<byte> issuer, Uri uri)
	{
		return $"{Convert.ToHexString(issuer.Span)} {uri.AbsoluteUri}";
	}

	// The other schemes, such as ldap, are skipped (RFC 5280, Secs. 4.2.2.1 and 4.2.1.13).
	private static Uri? ParseHttpUri(string text)
	{
		return Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) && uri.Scheme is "http" or "https" ? uri : null;
	}

	// RFC 6960, Appendix A.1: {url}/{url-encoding of base-64 encoding of the request}, if short enough for RFC 9919, Sec. 6; a URI with a query or a fragment has no place to append it.
	private static Uri? GetOcspGetUri(Uri responder, OcspRequest request)
	{
		if (responder.Query.Length > 0 || responder.Fragment.Length > 0)
		{
			return null;
		}

		string uri = $"{responder.AbsoluteUri.TrimEnd('/')}/{Uri.EscapeDataString(Convert.ToBase64String(request.Encoded.Span))}";
		return uri.Length <= MaxOcspGetLength ? new Uri(uri) : null;
	}

	// Returns whether the pool grew, so that the search is worth repeating. A round goes through its sources until one adds a certificate:
	// the certificates at which the strict search ended, as a retrieved issuer may be valid where one in the pool is not; what the URIs that the cache answered give now, as a kept certificate may be of another key of the same name; every known certificate, as a path can fail with no certificate left without an issuer; and again what the URIs that the cache answered in the previous source give now.
	private async ValueTask<bool> RetrieveIssuersAsync()
	{
		RetrievalState state = Retrieval;

		if (state.DeadEnds is not { } deadEnds || _validator.Caches is not { } caches)
		{
			return false;
		}

		int before = _pool.Count;
		bool roundCounted = false;

		for (int source = 0; source < 4 && _pool.Count == before; ++source)
		{
			List<IssuerRequest> requests = source switch
			{
				0 => GetIssuerRequests(deadEnds),
				1 or 3 => TakeCachedIssuerRequests(),
				_ => GetIssuerRequests([_leaf, .. _pool])
			};

			if (requests.Count is 0)
			{
				continue;
			}

			if (!roundCounted)
			{
				if (state.IssuerRoundsLeft is 0)
				{
					LimitRetrieval($"{MaxIssuerRounds} rounds of retrieving issuers");
					return false;
				}

				--state.IssuerRoundsLeft;
				roundCounted = true;
			}

			await RetrieveIssuersAsync(requests, source is 1 or 3 ? null : caches.Issuers).ConfigureAwait(false);
		}

		if (_pool.Count == before)
		{
			return false;
		}

		_leaf.Candidates = null;

		foreach (PathNode node in _pool)
		{
			node.Candidates = null;
		}

		return true;
	}

	private async ValueTask RetrieveIssuersAsync(List<IssuerRequest> requests, RetrievalCache<string, RetrievedIssuers>? cache)
	{
		RetrievalState state = Retrieval;

		foreach (IssuerRequest request in requests)
		{
			if (cache is not null && cache.TryGet(request.Key, _time, out RetrievedIssuers? cached))
			{
				AddIssuers(cached, requester: null);
				(state.CachedIssuerKeys ??= []).Add(request);
				continue;
			}

			if (state.RetrievalsLeft is 0 || state.RetrievedBytesLeft is 0)
			{
				LimitRetrieval($"{MaxRetrievals} retrievals or {MaxRetrievedBytes} bytes");
				break;
			}

			ReadOnlyMemory<byte> data = await RetrieveAsync(request.Uri, default, MaxCertificateLength).ConfigureAwait(false);

			if (!data.IsEmpty && RetrievedCertificates.Read(data, MaxCertificatesPerRetrieval) is { } certificates)
			{
				AddIssuers(new RetrievedIssuers(request.Key, certificates, data.Length), request.Requester);
			}
		}
	}

	// A self-signed certificate has no other issuer to find.
	private List<IssuerRequest> GetIssuerRequests(List<PathNode> nodes)
	{
		RetrievalState state = Retrieval;
		List<IssuerRequest> requests = [];

		foreach (PathNode node in nodes)
		{
			// The check of whether the certificate is self-signed may stop the search at its limit of candidates.
			if (IsSelfSigned(node) || _stopped)
			{
				continue;
			}

			IReadOnlyList<string> locations = node.Certificate.DecodedExtensions.AuthorityInformationAccess.Value?.CAIssuersUris ?? [];

			for (int i = 0; i < locations.Count; ++i)
			{
				if (ParseHttpUri(locations[i]) is not { } uri)
				{
					continue;
				}

				string key = GetCacheKey(node.Certificate.Issuer, uri);

				if ((state.TriedIssuerKeys ??= new HashSet<string>(StringComparer.Ordinal)).Add(key))
				{
					requests.Add(new IssuerRequest(uri, key, node));
				}
			}
		}

		return requests;
	}

	// Each request leaves the list, so that it is retrieved at most once in a validation.
	private List<IssuerRequest> TakeCachedIssuerRequests()
	{
		RetrievalState state = Retrieval;
		List<IssuerRequest> requests = state.CachedIssuerKeys ?? [];
		state.CachedIssuerKeys = null;
		return requests;
	}

	// The requester is the certificate whose URI gave these issuers, null if they come from the cache.
	private void AddIssuers(RetrievedIssuers retrieved, PathNode? requester)
	{
		RetrievalState state = Retrieval;

		foreach (Certificate certificate in retrieved.Certificates)
		{
			if (_validator.FindAnchor(certificate) is not null || !state.Encodings.Add(certificate.Encoded))
			{
				continue;
			}

			if (state.RetrievedIssuersLeft is 0)
			{
				LimitRetrieval($"{MaxRetrievedIssuers} retrieved certificates");
				return;
			}

			--state.RetrievedIssuersLeft;
			PathNode node = new(certificate, PathRole.Intermediate, _nextIndex++);
			_pool.Add(node);

			if (requester is not null)
			{
				(state.Sources ??= [])[node] = (retrieved, requester);
			}
		}
	}

	// Only an issuer that a path verified, for the very certificate that named its URI, is cached: what a certificate off the path retrieved says nothing, as the peer chooses its URIs and its name.
	private void KeepRetrievedIssuers(PathNode[] path)
	{
		if (_retrieval?.Sources is not { } sources || _validator.Caches is not { } caches)
		{
			return;
		}

		for (int i = 1; i < path.Length; ++i)
		{
			if (sources.TryGetValue(path[i], out (RetrievedIssuers Retrieved, PathNode Requester) source) && source.Requester == path[i - 1])
			{
				sources.Remove(path[i]);
				caches.Issuers.Add(source.Retrieved.Key, source.Retrieved, source.Retrieved.Size, _time + IssuerCacheLifetime, _time);
			}
		}
	}

	private void LimitRetrieval(string limit)
	{
		Retrieval.Limit ??= new PathProblem(CertificateValidationError.Unspecified, $"The retrieval of issuers stopped at the limit of {limit}.");
	}

	// RFC 5280, Sec. 6.3; the trust anchor is trusted as it is. Returns null if nothing keeps the path from being valid, the problem of the first revoked certificate, or that of the first whose status is unknown if that is an error. The edge of a certificate with a problem is marked, so that the search does not follow it again.
	private async ValueTask<PathProblem?> CheckRevocationAsync(PathNode[] path)
	{
		int count = _validator.RevocationFlag is X509RevocationFlag.EndCertificateOnly ? 1 : path.Length - 1;
		PathProblem? unknown = null;
		long unknownEdge = 0;

		for (int i = 0; i < count; ++i)
		{
			PathNode certificate = path[i];
			PathNode issuer = path[i + 1];
			RevocationResult result = await GetRevocationAsync(certificate, issuer).ConfigureAwait(false);

			switch (result.Status)
			{
				case RevocationStatus.Good:
				{
					break;
				}
				case RevocationStatus.Revoked:
				{
					(Retrieval.RejectedEdges ??= []).Add(EdgeOf(certificate, issuer));
					return new PathProblem(CertificateValidationError.Revoked, string.Create(CultureInfo.InvariantCulture, $"{{0}} was revoked on {result.RevocationTime:u} with the reason {result.Reason}."), certificate);
				}
				default:
				{
					if (!_validator.IgnoreRevocationUnknown && unknown is null)
					{
						unknown = new PathProblem(CertificateValidationError.RevocationUnknown, $"The revocation status of {{0}} could not be determined: {PathProblem.Escape(result.Detail ?? "no source covers it.")}", certificate);
						unknownEdge = EdgeOf(certificate, issuer);
					}

					break;
				}
			}
		}

		if (unknown is not null)
		{
			(Retrieval.RejectedEdges ??= []).Add(unknownEdge);
		}

		return unknown;
	}

	// Once for each pair, as a repeated search goes over the same edges again.
	private async ValueTask<RevocationResult> GetRevocationAsync(PathNode certificate, PathNode issuer)
	{
		RetrievalState state = Retrieval;
		long edge = EdgeOf(certificate, issuer);

		if (state.RevocationResults is not null && state.RevocationResults.TryGetValue(edge, out RevocationResult known))
		{
			return known;
		}

		RevocationResult result = await FindRevocationAsync(certificate.Certificate, issuer).ConfigureAwait(false);
		(state.RevocationResults ??= []).Add(edge, result);
		return result;
	}

	// A source that says Good or Revoked decides; otherwise the next is asked. CRLs for some reasons alone combine (RFC 5280, Sec. 6.3.3).
	private async ValueTask<RevocationResult> FindRevocationAsync(Certificate certificate, PathNode issuer)
	{
		// RFC 9608, Sec. 4: with the noRevAvail or ocsp-nocheck extension, step (a)(3) of RFC 5280, Sec. 6.1.3, is skipped, so no source is asked, not even the CRLs that the caller gave.
		if (certificate.DecodedExtensions.IsExemptFromRevocationCheck)
		{
			return new RevocationResult(RevocationStatus.Good);
		}

		// The strict search kept every issuer's key.
		if (issuer.Key is not { } key)
		{
			return new RevocationResult(RevocationStatus.Unknown, "The key of the issuer is not available.");
		}

		CrlReasonFlags covered = CrlReasonFlags.None;
		string? detail = null;

		foreach (CertificateRevocationList crl in _validator.FindRevocationLists(certificate.Issuer))
		{
			RevocationResult result = RevocationChecker.CheckCrl(crl, certificate, issuer.Certificate, key, _time);

			if (result.Status is RevocationStatus.Revoked)
			{
				return result;
			}

			covered |= result.CoveredReasons;
			detail ??= result.Detail;
		}

		// Every CRL has been looked at, so that one that revokes wins over one that does not.
		if ((covered & RevocationChecker.AllReasons) == RevocationChecker.AllReasons)
		{
			return new RevocationResult(RevocationStatus.Good);
		}

		if (_validator.RevocationMode is X509RevocationMode.Online)
		{
			RevocationResult ocsp = await QueryOcspAsync(certificate, issuer.Certificate).ConfigureAwait(false);

			if (ocsp.Status is RevocationStatus.Good or RevocationStatus.Revoked)
			{
				return ocsp;
			}

			detail ??= ocsp.Detail;

			RevocationResult crls = await CheckDistributionPointsAsync(certificate, issuer.Certificate, key, covered).ConfigureAwait(false);

			if (crls.Status is RevocationStatus.Good or RevocationStatus.Revoked)
			{
				return crls;
			}

			detail ??= crls.Detail;
		}

		return new RevocationResult(RevocationStatus.Unknown, detail);
	}

	// RFC 9919, Sec. 7.1, has a client cache every response that it validated. Here only good and revoked end the responders and are cached, as another responder may know a certificate that one signs as unknown. Whichever request it answers, a response is kept under the key of the SHA-256 request, the only one looked up, so that the next validation does not first send a request that fails.
	private async ValueTask<RevocationResult> QueryOcspAsync(Certificate certificate, Certificate issuer)
	{
		IReadOnlyList<string> locations = certificate.DecodedExtensions.AuthorityInformationAccess.Value?.OcspUris ?? [];

		if (locations.Count is 0 || _validator.Caches is not { } caches)
		{
			return new RevocationResult(RevocationStatus.Unknown);
		}

		OcspRequest request = OcspRequest.Create(certificate, issuer);

		if (caches.OcspResponses.TryGet(request.Encoded, _time, out OcspResponse? cached))
		{
			RevocationResult result = CheckOcsp(cached, certificate, issuer);

			if (result.Status is RevocationStatus.Good or RevocationStatus.Revoked)
			{
				return result;
			}
		}

		OcspRequest? sha1Request = null;
		string? detail = null;

		for (int i = 0; i < locations.Count; ++i)
		{
			if (ParseHttpUri(locations[i]) is not { } responder)
			{
				continue;
			}

			(RevocationResult Result, OcspResponse? Response, int Length)? answer = await AskOcspAsync(responder, request, certificate, issuer).ConfigureAwait(false);

			// RFC 9919, Sec. 3.1.1, still allows for SHA-1 in older implementations, and a responder may refuse a SHA-256 CertID or not know it. One that could not be reached is not asked again.
			if (answer is { Result.Status: not (RevocationStatus.Good or RevocationStatus.Revoked) } inconclusive)
			{
				detail ??= inconclusive.Result.Detail;
				sha1Request ??= OcspRequest.Create(certificate, issuer, hashAlgorithm: HashAlgorithmName.SHA1);
				answer = await AskOcspAsync(responder, sha1Request, certificate, issuer).ConfigureAwait(false);
			}

			if (answer is not { Result: { Status: RevocationStatus.Good or RevocationStatus.Revoked } result, Response: { } response, Length: var length })
			{
				detail ??= answer?.Result.Detail ?? "An OCSP responder could not be reached.";
				continue;
			}

			if (result.NextUpdate is { } nextUpdate)
			{
				caches.OcspResponses.Add(request.Encoded, response, length, nextUpdate, _time);
			}

			return result;
		}

		return new RevocationResult(RevocationStatus.Unknown, detail);
	}

	// Asks a responder once. Null if nothing came back; a Response of null if what came back does not decode.
	private async ValueTask<(RevocationResult Result, OcspResponse? Response, int Length)?> AskOcspAsync(Uri responder, OcspRequest request, Certificate certificate, Certificate issuer)
	{
		ReadOnlyMemory<byte> data = GetOcspGetUri(responder, request) is { } get
			? await RetrieveAsync(get, default, MaxOcspResponseLength).ConfigureAwait(false)
			: await RetrieveAsync(responder, request.Encoded, MaxOcspResponseLength).ConfigureAwait(false);

		if (data.IsEmpty)
		{
			return null;
		}

		OcspResponse response;

		try
		{
			response = OcspResponse.Decode(data.Span);
		}
		catch (ArgumentException)
		{
			return (new RevocationResult(RevocationStatus.Invalid, "An OCSP response does not decode."), null, data.Length);
		}

		RevocationResult result = CheckOcsp(response, certificate, issuer);
		return (result.Status is RevocationStatus.Unknown ? result with { Detail = "An OCSP responder does not know the certificate." } : result, response, data.Length);
	}

	private RevocationResult CheckOcsp(OcspResponse response, Certificate certificate, Certificate issuer)
	{
		return RevocationChecker.CheckOcsp(response, certificate, issuer, _validator.ImportPublicKey, _time, minRsaKeySize: _validator.MinRsaKeySize);
	}

	// RFC 5280, Sec. 6.3.3 (b)(1): only the points that name the certificate's own issuer, as a cRLIssuer is for an indirect CRL, which is not supported.
	private async ValueTask<RevocationResult> CheckDistributionPointsAsync(Certificate certificate, Certificate issuer, ISignatureKey key, CrlReasonFlags covered)
	{
		string? detail = null;

		foreach (CrlDistributionPoint point in certificate.DecodedExtensions.CrlDistributionPoints.Value ?? [])
		{
			if (point.CrlIssuer is not null || point.DistributionPoint is not { } name)
			{
				continue;
			}

			// Sec. 4.2.1.13: the names of a point are different ways to get the same CRL, so one that is usable is enough.
			for (int i = 0; i < name.Uris.Count; ++i)
			{
				if (ParseHttpUri(name.Uris[i]) is not { } uri)
				{
					continue;
				}

				string cacheKey = GetCacheKey(certificate.Issuer, uri);

				if (await GetCrlAsync(uri, cacheKey, certificate, issuer, key).ConfigureAwait(false) is not ({ } crl, var result))
				{
					detail ??= "A CRL could not be retrieved or decoded.";
					continue;
				}

				if (result.Status is RevocationStatus.Revoked)
				{
					KeepCrl(cacheKey, crl);
					return result;
				}

				if (result.CoveredReasons is not CrlReasonFlags.None)
				{
					KeepCrl(cacheKey, crl);
					covered |= result.CoveredReasons;

					if ((covered & RevocationChecker.AllReasons) == RevocationChecker.AllReasons)
					{
						return new RevocationResult(RevocationStatus.Good);
					}

					break;
				}

				detail ??= result.Detail;
			}
		}

		return new RevocationResult(RevocationStatus.Unknown, detail);
	}

	// Only a verified CRL is kept, so that nobody can hide the real one behind a bad copy.
	private void KeepCrl(string cacheKey, CertificateRevocationList crl)
	{
		if (_validator.Caches is { } caches && crl.NextUpdate is { } nextUpdate)
		{
			caches.Crls.Add(cacheKey, crl, crl.Encoded.Length, nextUpdate, _time);
		}
	}

	// A kept CRL that decides nothing, as it may be of another key of the same name, gives way to the one at the URI.
	private async ValueTask<(CertificateRevocationList Crl, RevocationResult Result)?> GetCrlAsync(Uri uri, string cacheKey, Certificate certificate, Certificate issuer, ISignatureKey key)
	{
		if (_validator.Caches is { } caches && caches.Crls.TryGet(cacheKey, _time, out CertificateRevocationList? cached))
		{
			RevocationResult kept = RevocationChecker.CheckCrl(cached, certificate, issuer, key, _time);

			if (kept.Status is RevocationStatus.Revoked || kept.CoveredReasons is not CrlReasonFlags.None)
			{
				return (cached, kept);
			}
		}

		return await RetrieveCrlAsync(uri, cacheKey).ConfigureAwait(false) is { } crl ? (crl, RevocationChecker.CheckCrl(crl, certificate, issuer, key, _time)) : null;
	}

	// Retrieved once in a validation for each of its keys in the cache, whether or not it decoded.
	private async ValueTask<CertificateRevocationList?> RetrieveCrlAsync(Uri uri, string cacheKey)
	{
		RetrievalState state = Retrieval;

		if (state.RetrievedCrls is not null && state.RetrievedCrls.TryGetValue(cacheKey, out CertificateRevocationList? known))
		{
			return known;
		}

		ReadOnlyMemory<byte> data = await RetrieveAsync(uri, default, MaxCrlLength).ConfigureAwait(false);
		CertificateRevocationList? crl = null;

		if (!data.IsEmpty)
		{
			try
			{
				crl = CertificateRevocationList.Decode(data.Span);
			}
			catch (ArgumentException)
			{
			}
		}

		(state.RetrievedCrls ??= new Dictionary<string, CertificateRevocationList?>(StringComparer.Ordinal))[cacheKey] = crl;
		return crl;
	}

	// Empty if nothing may be retrieved any more, as by the limits or the deadline, or if the retrieval fails or returns more than limit. Only the cancellation of the validation throws.
	private async ValueTask<ReadOnlyMemory<byte>> RetrieveAsync(Uri uri, ReadOnlyMemory<byte> content, int limit)
	{
		RetrievalState state = Retrieval;
		int maxLength = (int)Math.Min(limit, state.RetrievedBytesLeft);

		if (_validator.Retriever is not { } retriever || state.RetrievalsLeft is 0 || maxLength is 0)
		{
			return default;
		}

		_cancellationToken.ThrowIfCancellationRequested();

		TimeSpan? left = PlatformCertificateValidator.RetrievalLimit(_context.Deadline, _context.TimeProvider.GetUtcNow());

		if (left == TimeSpan.Zero)
		{
			return default;
		}

		--state.RetrievalsLeft;

		using CancellationTokenSource? timeout = left is { } time && time <= MaxDeadlineTimer ? new CancellationTokenSource(time, _context.TimeProvider) : null;
		using CancellationTokenSource? linked = timeout is null ? null : CancellationTokenSource.CreateLinkedTokenSource(_cancellationToken, timeout.Token);
		CancellationToken token = linked?.Token ?? _cancellationToken;

		try
		{
			ReadOnlyMemory<byte> data = content.IsEmpty
				? await retriever.GetAsync(uri, maxLength, token).ConfigureAwait(false)
				: await retriever.PostAsync(uri, content, OcspRequestMediaType, maxLength, token).ConfigureAwait(false);

			if (data.Length > maxLength)
			{
				return default;
			}

			state.RetrievedBytesLeft -= data.Length;
			return data;
		}
		catch (OperationCanceledException) when (!_cancellationToken.IsCancellationRequested)
		{
			return default;
		}
	}

	private readonly record struct IssuerRequest(Uri Uri, string Key, PathNode Requester);

	// The collections are created when first needed.
	private sealed class RetrievalState(HashSet<ReadOnlyMemory<byte>> encodings, bool retrievesIssuers)
	{
		// The encodings of the peer's certificate and of the pool, which also takes the retrieved certificates.
		public HashSet<ReadOnlyMemory<byte>> Encodings { get; } = encodings;

		// Null if the validator does not retrieve issuers.
		public List<PathNode>? DeadEnds { get; } = retrievesIssuers ? [] : null;

		// The retrievals that gave the certificates of the pool that the cache does not hold, each with the certificate whose URI caused it, to cache them once a path has used them as the issuer of that certificate.
		public Dictionary<PathNode, (RetrievedIssuers Retrieved, PathNode Requester)>? Sources { get; set; }

		public HashSet<string>? TriedIssuerKeys { get; set; }

		public List<IssuerRequest>? CachedIssuerKeys { get; set; }

		// Null for a retrieval that failed.
		public Dictionary<string, CertificateRevocationList?>? RetrievedCrls { get; set; }

		public Dictionary<long, RevocationResult>? RevocationResults { get; set; }

		// The pairs that revocation rejects, which the search does not follow again.
		public HashSet<long>? RejectedEdges { get; set; }

		public int IssuerRoundsLeft { get; set; } = MaxIssuerRounds;

		public int RetrievedIssuersLeft { get; set; } = MaxRetrievedIssuers;

		public int RetrievalsLeft { get; set; } = MaxRetrievals;

		public long RetrievedBytesLeft { get; set; } = MaxRetrievedBytes;

		public PathProblem? Limit { get; set; }
	}
}
