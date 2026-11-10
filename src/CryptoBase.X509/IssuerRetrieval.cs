namespace CryptoBase.X509;

// The retrieval of the issuers that the certificates of one validation lack, from their id-ad-caIssuers URIs (RFC 5280, Sec. 4.2.2.1), and the caching of those that a path verified.
// The search fills DeadEnds, tells RetrieveAsync which certificates have an issuer to find, as that check counts towards its own limits, adds what RetrieveAsync returns to its candidates, and gives Keep each path that its strict search returns.
internal sealed class IssuerRetrieval(TrustAnchorCertificateValidator validator, RetrievalCaches caches, RetrievalBudget budget, HashSet<ReadOnlyMemory<byte>> encodings, DateTimeOffset time)
{
	// Certificates at a URI change rarely, and each is checked at every use.
	private static readonly TimeSpan CacheLifetime = TimeSpan.FromHours(1);

	// The retrievals that gave the retrieved certificates that the cache does not hold, each with the certificate whose URI caused it, to cache them once a path has used them as the issuer of that certificate.
	private Dictionary<Certificate, (RetrievedIssuers Retrieved, PathNode Requester)>? _sources;

	private HashSet<string>? _triedKeys;

	private List<IssuerRequest>? _cachedRequests;

	// The certificates at which the strict search ended without an issuer, which it fills.
	public List<PathNode> DeadEnds { get; } = [];

	// The certificates that a round adds to the candidates, in order, each new to the validation and none a trust anchor; empty if the search is not worth repeating. A round goes through its sources until one adds a certificate:
	// the certificates at which the strict search ended, as a retrieved issuer may be valid where one in the pool is not; what the URIs that the cache answered give now, as a kept certificate may be of another key of the same name; every known certificate, as a path can fail with no certificate left without an issuer; and again what the URIs that the cache answered in the previous source give now.
	public async ValueTask<List<Certificate>> RetrieveAsync(PathNode leaf, IReadOnlyList<PathNode> pool, Func<PathNode, bool> hasIssuerToFind)
	{
		List<Certificate> added = [];
		bool roundCounted = false;

		for (int source = 0; source < 4 && added.Count is 0; ++source)
		{
			List<IssuerRequest> requests = source switch
			{
				0 => GetRequests(DeadEnds, hasIssuerToFind),
				1 or 3 => TakeCachedRequests(),
				_ => GetRequests([leaf, .. pool], hasIssuerToFind)
			};

			if (requests.Count is 0)
			{
				continue;
			}

			if (!roundCounted)
			{
				if (!budget.TryStartIssuerRound())
				{
					return added;
				}

				roundCounted = true;
			}

			await RetrieveAsync(requests, source is 1 or 3 ? null : caches.Issuers, added).ConfigureAwait(false);
		}

		return added;
	}

	// Only an issuer that a path verified, for the very certificate that named its URI, is cached: what a certificate off the path retrieved says nothing, as the peer chooses its URIs and its name.
	public void Keep(PathNode[] path)
	{
		if (_sources is not { } sources)
		{
			return;
		}

		for (int i = 1; i < path.Length; ++i)
		{
			if (sources.TryGetValue(path[i].Certificate, out (RetrievedIssuers Retrieved, PathNode Requester) source) && source.Requester == path[i - 1])
			{
				sources.Remove(path[i].Certificate);
				caches.Issuers.Add(source.Retrieved.Key, source.Retrieved, source.Retrieved.Size, time + CacheLifetime, time);
			}
		}
	}

	private async ValueTask RetrieveAsync(List<IssuerRequest> requests, RetrievalCache<string, RetrievedIssuers>? cache, List<Certificate> added)
	{
		foreach (IssuerRequest request in requests)
		{
			if (cache is not null && cache.TryGet(request.Key, time, out RetrievedIssuers? cached))
			{
				Add(cached, requester: null, added);
				(_cachedRequests ??= []).Add(request);
				continue;
			}

			if (!budget.CanRetrieveIssuers())
			{
				break;
			}

			ReadOnlyMemory<byte> data = await budget.GetAsync(request.Uri, RetrievalBudget.MaxCertificateLength).ConfigureAwait(false);

			if (!data.IsEmpty && RetrievedCertificates.Read(data, RetrievalBudget.MaxCertificatesPerRetrieval) is { } certificates)
			{
				Add(new RetrievedIssuers(request.Key, certificates, data.Length), request.Requester, added);
			}
		}
	}

	// A certificate without an issuer to find, such as a self-signed one, names none.
	private List<IssuerRequest> GetRequests(List<PathNode> nodes, Func<PathNode, bool> hasIssuerToFind)
	{
		List<IssuerRequest> requests = [];

		foreach (PathNode node in nodes)
		{
			if (!hasIssuerToFind(node))
			{
				continue;
			}

			IReadOnlyList<string> locations = node.Certificate.DecodedExtensions.AuthorityInformationAccess.Value?.CAIssuersUris ?? [];

			for (int i = 0; i < locations.Count; ++i)
			{
				if (RetrievalBudget.ParseHttpUri(locations[i]) is not { } uri)
				{
					continue;
				}

				string key = RetrievalCaches.GetKey(node.Certificate.Issuer, uri);

				if ((_triedKeys ??= new HashSet<string>(StringComparer.Ordinal)).Add(key))
				{
					requests.Add(new IssuerRequest(uri, key, node));
				}
			}
		}

		return requests;
	}

	// Each request leaves the list, so that it is retrieved at most once in a validation.
	private List<IssuerRequest> TakeCachedRequests()
	{
		List<IssuerRequest> requests = _cachedRequests ?? [];
		_cachedRequests = null;
		return requests;
	}

	// The requester is the certificate whose URI gave these issuers, null if they come from the cache.
	private void Add(RetrievedIssuers retrieved, PathNode? requester, List<Certificate> added)
	{
		foreach (Certificate certificate in retrieved.Certificates)
		{
			if (validator.FindAnchor(certificate) is not null || !encodings.Add(certificate.Encoded))
			{
				continue;
			}

			if (!budget.TryAddIssuer())
			{
				return;
			}

			added.Add(certificate);

			if (requester is not null)
			{
				(_sources ??= [])[certificate] = (retrieved, requester);
			}
		}
	}

	private readonly record struct IssuerRequest(Uri Uri, string Key, PathNode Requester);
}
