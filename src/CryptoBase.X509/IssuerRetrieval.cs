namespace CryptoBase.X509;

// The retrieval of the issuers that the certificates of one validation lack, from their id-ad-caIssuers URIs (RFC 5280, Sec. 4.2.2.1), and the caching of those that a path verified.
// The search fills DeadEnds, tells RetrieveAsync which certificates have an issuer to find, as that check counts towards its own limits, adds what RetrieveAsync returns to its candidates, and gives Keep each path that its strict search returns.
internal sealed class IssuerRetrieval(TrustAnchorCertificateValidator validator, RetrievalCaches caches, RetrievalBudget budget, HashSet<ReadOnlyMemory<byte>> encodings, DateTimeOffset time)
{
	// The first retrieval that gave each certificate, by its encoding, to cache it once a path has used it above the certificate whose URI gave it.
	private Dictionary<ReadOnlyMemory<byte>, IssuerSource>? _sources;

	private HashSet<RetrievalKey>? _triedKeys;

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

	public void Keep(PathNode[] path)
	{
		if (_sources is { } sources)
		{
			caches.Issuers.Keep(path, sources, time);
		}
	}

	private async ValueTask RetrieveAsync(List<IssuerRequest> requests, IssuerCache? cache, List<Certificate> added)
	{
		foreach (IssuerRequest request in requests)
		{
			// A kept issuer counts towards the retrieved certificates like any other, as each costs the search a key and its checks; an entry holds only the certificates of a path that its key gave, at most those of one retrieval.
			if (cache is not null && cache.TryGet(request.Key, time, out Certificate[]? cached))
			{
				Add(cached, source: null, added);
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
				Add(certificates, new IssuerSource(request.Key, request.Requester), added);
			}
		}
	}

	// A certificate without an issuer to find, such as a self-signed one, names none. Once the budget has no request left, the URIs that follow are left out, as are those of every later round.
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
			byte[]? issuerDigest = null;

			for (int i = 0; i < locations.Count; ++i)
			{
				if (RetrievalBudget.ParseHttpUri(locations[i]) is not { } uri)
				{
					continue;
				}

				RetrievalKey key = RetrievalKey.Create(issuerDigest ??= RetrievalKey.DigestIssuer(node.Certificate.Issuer.Span), uri);

				if ((_triedKeys ??= []).Contains(key))
				{
					continue;
				}

				if (!budget.TryPrepareIssuerRequest())
				{
					return requests;
				}

				_triedKeys.Add(key);
				requests.Add(new IssuerRequest(uri, key, node));
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

	// The source is the retrieval that gave these certificates, null if they come from the cache.
	// A certificate that the validation already has, from the peer or from the cache, still takes the source, so that the entry of a path holds every certificate of it that the URI gives: a validation that lacks one need not retrieve the URI again.
	private void Add(Certificate[] certificates, IssuerSource? source, List<Certificate> added)
	{
		foreach (Certificate certificate in certificates)
		{
			if (validator.FindAnchor(certificate) is not null)
			{
				continue;
			}

			bool isNew = encodings.Add(certificate.Encoded);

			if (isNew && !budget.TryAddIssuer())
			{
				return;
			}

			if (source is { } value)
			{
				(_sources ??= new Dictionary<ReadOnlyMemory<byte>, IssuerSource>(ByteMemoryComparer.Instance)).TryAdd(certificate.Encoded, value);
			}

			if (isNew)
			{
				added.Add(certificate);
			}
		}
	}

	private readonly record struct IssuerRequest(Uri Uri, RetrievalKey Key, PathNode Requester);
}
