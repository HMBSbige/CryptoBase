using System.Globalization;

namespace CryptoBase.X509;

// The revocation checks of the paths of one validation (RFC 5280, Sec. 6.3): the CRLs that the caller gave and, online, the OCSP responders and CRL distribution points of each certificate, retrieved within the budget.
// The search gives CheckAsync each path that passes every other check, and follows no edge again that it rejects.
internal sealed class PathRevocation(TrustAnchorCertificateValidator validator, RetrievalBudget budget, DateTimeOffset time)
{
	// RFC 9919, Sec. 6: a request of at most this many bytes after encoding, with the scheme and server name, must use GET.
	private const int MaxOcspGetLength = 255;
	private const string OcspRequestMediaType = "application/ocsp-request";

	private static readonly string RequestLimitDetail = $"The validation reached its limit of {RetrievalBudget.MaxRequests} requests from the URIs of the certificates.";

	private Dictionary<long, RevocationResult>? _results;

	private HashSet<long>? _rejectedEdges;

	// Null for a retrieval that failed.
	private Dictionary<RetrievalKey, CertificateRevocationList?>? _retrievedCrls;

	public int RejectedEdgeCount => _rejectedEdges?.Count ?? 0;

	public bool IsRejected(PathNode certificate, PathNode issuer)
	{
		return _rejectedEdges?.Contains(certificate.PairWith(issuer)) is true;
	}

	// The trust anchor is trusted as it is. Returns null if nothing keeps the path from being valid, the problem of the first revoked certificate, or that of the first whose status is unknown if that is an error. The edge of a certificate with a problem is rejected, so that the search does not follow it again.
	public async ValueTask<PathProblem?> CheckAsync(PathNode[] path)
	{
		int count = validator.RevocationFlag is X509RevocationFlag.EndCertificateOnly ? 1 : path.Length - 1;
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
					(_rejectedEdges ??= []).Add(certificate.PairWith(issuer));
					return new PathProblem(CertificateValidationError.Revoked, string.Create(CultureInfo.InvariantCulture, $"{{0}} was revoked on {result.RevocationTime:u} with the reason {result.Reason}."), certificate);
				}
				default:
				{
					if (!validator.IgnoreRevocationUnknown && unknown is null)
					{
						unknown = new PathProblem(CertificateValidationError.RevocationUnknown, $"The revocation status of {{0}} could not be determined: {PathProblem.Escape(result.Detail ?? "no source covers it.")}", certificate);
						unknownEdge = certificate.PairWith(issuer);
					}

					break;
				}
			}
		}

		if (unknown is not null)
		{
			(_rejectedEdges ??= []).Add(unknownEdge);
		}

		return unknown;
	}

	// RFC 6960, Appendix A.1: {url}/{url-encoding of base-64 encoding of the request}, if short enough for RFC 9919, Sec. 6; a URI with a query or a fragment has no place to append it.
	// The URI is kept whole, with a slash added only if it does not end with one, as the OCSP client of the .NET runtime on OpenSSL appends it: removing slashes would ask another resource of a responder whose path ends with several.
	private static Uri? GetOcspGetUri(Uri responder, OcspRequest request)
	{
		if (responder.Query.Length > 0 || responder.Fragment.Length > 0)
		{
			return null;
		}

		string url = responder.AbsoluteUri;
		string uri = $"{url}{(url.EndsWith('/') ? "" : "/")}{Uri.EscapeDataString(Convert.ToBase64String(request.Encoded.Span))}";
		return uri.Length <= MaxOcspGetLength ? new Uri(uri) : null;
	}

	// Once for each pair, as a repeated search goes over the same edges again.
	private async ValueTask<RevocationResult> GetRevocationAsync(PathNode certificate, PathNode issuer)
	{
		long edge = certificate.PairWith(issuer);

		if (_results is not null && _results.TryGetValue(edge, out RevocationResult known))
		{
			return known;
		}

		RevocationResult result = await FindRevocationAsync(certificate.Certificate, issuer).ConfigureAwait(false);
		(_results ??= []).Add(edge, result);
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

		foreach (CertificateRevocationList crl in validator.FindRevocationLists(certificate.Issuer))
		{
			RevocationResult result = RevocationChecker.CheckCrl(crl, certificate, issuer.Certificate, key, time);

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

		if (validator.RevocationMode is X509RevocationMode.Online)
		{
			RevocationResult ocsp = await QueryOcspAsync(certificate, issuer.Certificate).ConfigureAwait(false);

			if (ocsp.IsConclusive)
			{
				return ocsp;
			}

			detail ??= ocsp.Detail;

			RevocationResult crls = await CheckDistributionPointsAsync(certificate, issuer.Certificate, key, covered).ConfigureAwait(false);

			if (crls.IsConclusive)
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

		if (locations.Count is 0 || validator.Caches is not { } caches)
		{
			return new RevocationResult(RevocationStatus.Unknown);
		}

		OcspRequest request = OcspRequest.Create(certificate, issuer);

		if (caches.OcspResponses.TryGet(request.Encoded, time, out OcspResponse? cached))
		{
			RevocationResult result = CheckOcsp(cached, certificate, issuer);

			if (result.IsConclusive)
			{
				return result;
			}
		}

		OcspRequest? sha1Request = null;
		string? detail = null;

		for (int i = 0; i < locations.Count; ++i)
		{
			if (RetrievalBudget.ParseHttpUri(locations[i]) is not { } responder)
			{
				continue;
			}

			if (!budget.TryPrepareRevocationRequest())
			{
				detail ??= RequestLimitDetail;
				break;
			}

			(RevocationResult Result, OcspResponse? Response)? answer = await AskOcspAsync(responder, request, certificate, issuer).ConfigureAwait(false);

			// RFC 9919, Sec. 3.1.1, still allows for SHA-1 in older implementations, and a responder may refuse a SHA-256 CertID or not know it. One that could not be reached is not asked again.
			if (answer is { Result.IsConclusive: false } inconclusive)
			{
				detail ??= inconclusive.Result.Detail;
				sha1Request ??= OcspRequest.Create(certificate, issuer, hashAlgorithm: HashAlgorithmName.SHA1);
				answer = await AskOcspAsync(responder, sha1Request, certificate, issuer).ConfigureAwait(false);
			}

			if (answer is not { Result: { IsConclusive: true } result, Response: { } response })
			{
				detail ??= answer?.Result.Detail ?? "An OCSP responder could not be reached.";
				continue;
			}

			if (result.NextUpdate is { } nextUpdate)
			{
				caches.OcspResponses.Add(request.Encoded, response, response.Encoded.Length, nextUpdate, time);
			}

			return result;
		}

		return new RevocationResult(RevocationStatus.Unknown, detail);
	}

	// Asks a responder once. Null if nothing came back; a Response of null if what came back does not decode.
	private async ValueTask<(RevocationResult Result, OcspResponse? Response)?> AskOcspAsync(Uri responder, OcspRequest request, Certificate certificate, Certificate issuer)
	{
		ReadOnlyMemory<byte> data = GetOcspGetUri(responder, request) is { } get
			? await budget.GetAsync(get, RetrievalBudget.MaxOcspResponseLength).ConfigureAwait(false)
			: await budget.PostAsync(responder, request.Encoded, OcspRequestMediaType, RetrievalBudget.MaxOcspResponseLength).ConfigureAwait(false);

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
			return (new RevocationResult(RevocationStatus.Invalid, "An OCSP response does not decode."), null);
		}

		RevocationResult result = CheckOcsp(response, certificate, issuer);
		return (result.Status is RevocationStatus.Unknown ? result with { Detail = "An OCSP responder does not know the certificate." } : result, response);
	}

	private RevocationResult CheckOcsp(OcspResponse response, Certificate certificate, Certificate issuer)
	{
		return RevocationChecker.CheckOcsp(response, certificate, issuer, validator.ImportPublicKey, time, minRsaKeySize: validator.MinRsaKeySize);
	}

	// RFC 5280, Sec. 6.3.3 (b)(1): only the points that name the certificate's own issuer, as a cRLIssuer is for an indirect CRL, which is not supported.
	private async ValueTask<RevocationResult> CheckDistributionPointsAsync(Certificate certificate, Certificate issuer, ISignatureKey key, CrlReasonFlags covered)
	{
		string? detail = null;
		byte[]? issuerDigest = null;

		foreach (CrlDistributionPoint point in certificate.DecodedExtensions.CrlDistributionPoints.Value ?? [])
		{
			if (point.CrlIssuer is not null || point.DistributionPoint is not { } name)
			{
				continue;
			}

			// Sec. 4.2.1.13: the names of a point are different ways to get the same CRL, so one that is usable is enough.
			for (int i = 0; i < name.Uris.Count; ++i)
			{
				if (RetrievalBudget.ParseHttpUri(name.Uris[i]) is not { } uri)
				{
					continue;
				}

				if (!budget.TryPrepareRevocationRequest())
				{
					return new RevocationResult(RevocationStatus.Unknown, detail ?? RequestLimitDetail);
				}

				RetrievalKey cacheKey = RetrievalKey.Create(issuerDigest ??= RetrievalKey.DigestIssuer(certificate.Issuer.Span), uri);

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
	private void KeepCrl(RetrievalKey cacheKey, CertificateRevocationList crl)
	{
		if (validator.Caches is { } caches && crl.NextUpdate is { } nextUpdate)
		{
			caches.Crls.Add(cacheKey, crl, crl.Encoded.Length, nextUpdate, time);
		}
	}

	// A kept CRL that decides nothing, as it may be of another key of the same name, gives way to the one at the URI.
	private async ValueTask<(CertificateRevocationList Crl, RevocationResult Result)?> GetCrlAsync(Uri uri, RetrievalKey cacheKey, Certificate certificate, Certificate issuer, ISignatureKey key)
	{
		if (validator.Caches is { } caches && caches.Crls.TryGet(cacheKey, time, out CertificateRevocationList? cached))
		{
			RevocationResult kept = RevocationChecker.CheckCrl(cached, certificate, issuer, key, time);

			if (kept.Status is RevocationStatus.Revoked || kept.CoveredReasons is not CrlReasonFlags.None)
			{
				return (cached, kept);
			}
		}

		return await RetrieveCrlAsync(uri, cacheKey).ConfigureAwait(false) is { } crl ? (crl, RevocationChecker.CheckCrl(crl, certificate, issuer, key, time)) : null;
	}

	// Retrieved once in a validation for each of its keys in the cache, whether or not it decoded.
	private async ValueTask<CertificateRevocationList?> RetrieveCrlAsync(Uri uri, RetrievalKey cacheKey)
	{
		if (_retrievedCrls is not null && _retrievedCrls.TryGetValue(cacheKey, out CertificateRevocationList? known))
		{
			return known;
		}

		ReadOnlyMemory<byte> data = await budget.GetAsync(uri, RetrievalBudget.MaxCrlLength).ConfigureAwait(false);
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

		(_retrievedCrls ??= [])[cacheKey] = crl;
		return crl;
	}
}
