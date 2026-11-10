using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.X509;

// What a validator keeps of what it retrieved, so that a validation need not retrieve it again: issuers and CRLs by the RetrievalKey of the URL and the issuer of the certificate that named it, and OCSP responses by CertID. Each holds only what has been verified, so that nobody can fill it or hide the real data behind a bad copy.
internal sealed class RetrievalCaches
{
	public IssuerCache Issuers { get; } = new();

	public RetrievalCache<RetrievalKey, CertificateRevocationList> Crls { get; } = new(64, 64L << 20, EqualityComparer<RetrievalKey>.Default);

	public RetrievalCache<ReadOnlyMemory<byte>, OcspResponse> OcspResponses { get; } = new(4096, 32L << 20, ByteMemoryComparer.Instance);
}

// The retrieval that gave a certificate of a validation: its key, and the certificate whose URI caused it.
internal readonly record struct IssuerSource(RetrievalKey Key, PathNode Requester);

// The issuers that paths verified, under the keys of the retrievals that gave them. It takes paths rather than certificates: what a URI gives besides the issuer, which anyone on the path of a plain http URI can add to, never enters it, so that it cannot fill the room of a later validation for the certificates that it retrieves.
// An entry holds the issuers that one path verified for its key, and the next path to verify one replaces it rather than adding to it, as a CRL that another key of the name signs replaces the one kept: what a URI gives may change, and every certificate of an entry is then one that the latest path used. A key whose certificates alternate between two issuers of the name costs one retrieval at each change, as it would without the cache.
internal sealed class IssuerCache
{
	// Certificates at a URI change rarely, and each is checked at every use.
	private static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);

	private readonly RetrievalCache<RetrievalKey, Certificate[]> _entries = new(256, 16L << 20, EqualityComparer<RetrievalKey>.Default);

	public bool TryGet(RetrievalKey key, DateTimeOffset time, [MaybeNullWhen(false)] out Certificate[] issuers)
	{
		return _entries.TryGet(key, time, out issuers);
	}

	// Keeps each certificate of the path that a retrieval for a certificate below it on the path gave: as the strict search returned the path, every check accepted the certificate above the very certificate that named its URI. What a certificate off the path retrieved says nothing, as the peer chooses its URIs and its name, and neither does what a URI gave below the certificate that named it, as no issuer of the key's name is there.
	// The certificates above the issuer count too, as a URI may give the whole chain, or a certificate of a new key of the name, which the old key issues, with the old key's own: a path that left them out would retrieve the URI at every validation. They make one entry, of at most the certificates of one retrieval, whose size is that of the certificates in it.
	public void Keep(PathNode[] path, IReadOnlyDictionary<ReadOnlyMemory<byte>, IssuerSource> sources, DateTimeOffset time)
	{
		Dictionary<RetrievalKey, List<Certificate>>? verified = null;

		for (int i = 1; i < path.Length; ++i)
		{
			Certificate issuer = path[i].Certificate;

			if (!sources.TryGetValue(issuer.Encoded, out IssuerSource source) || Array.IndexOf(path, source.Requester, 0, i) < 0)
			{
				continue;
			}

			verified ??= [];

			if (!verified.TryGetValue(source.Key, out List<Certificate>? issuers))
			{
				issuers = [];
				verified.Add(source.Key, issuers);
			}

			issuers.Add(issuer);
		}

		if (verified is null)
		{
			return;
		}

		foreach ((RetrievalKey key, List<Certificate> issuers) in verified)
		{
			int size = 0;

			foreach (Certificate issuer in issuers)
			{
				size += issuer.Encoded.Length;
			}

			_entries.Add(key, [.. issuers], size, Lifetime, time);
		}
	}
}

// A cache bounded in entries and bytes, whose entries are valid until a time of the validation that adds them. When it is full, the entries that expire first leave first, so an expired entry never displaces one that is still valid. Safe for concurrent use.
internal sealed class RetrievalCache<TKey, TValue>(int maxEntries, long maxBytes, IEqualityComparer<TKey> comparer) where TKey : notnull
{
	private readonly Lock _lock = new();
	private readonly Dictionary<TKey, Entry> _entries = new(comparer);
	private long _bytes;

	public bool TryGet(TKey key, DateTimeOffset time, [MaybeNullWhen(false)] out TValue value)
	{
		lock (_lock)
		{
			if (_entries.TryGetValue(key, out Entry? entry))
			{
				if (time < entry.Expires)
				{
					value = entry.Value;
					return true;
				}

				Remove(key, entry);
			}
		}

		value = default;
		return false;
	}

	// As the other Add, for an entry that lasts for lifetime from the time of the validation, or until the last time that DateTimeOffset holds if that comes first: the time comes from the caller's TimeProvider, and an expiry beyond that range would throw once a path had been found.
	public void Add(TKey key, TValue value, int size, TimeSpan lifetime, DateTimeOffset time)
	{
		Debug.Assert(lifetime > TimeSpan.Zero);

		// The difference of two times always fits a TimeSpan.
		DateTimeOffset expires = DateTimeOffset.MaxValue - time > lifetime ? time.ToUniversalTime() + lifetime : DateTimeOffset.MaxValue;
		Add(key, value, size, expires, time);
	}

	// Adds or replaces an entry, unless it has already expired or is too long for the cache.
	public void Add(TKey key, TValue value, int size, DateTimeOffset expires, DateTimeOffset time)
	{
		if (expires <= time || size > maxBytes)
		{
			return;
		}

		lock (_lock)
		{
			if (_entries.TryGetValue(key, out Entry? replaced))
			{
				Remove(key, replaced);
			}

			while (_entries.Count >= maxEntries || _bytes + size > maxBytes)
			{
				RemoveFirstToExpire();
			}

			_entries.Add(key, new Entry(value, size, expires));
			_bytes += size;
		}
	}

	private void Remove(TKey key, Entry entry)
	{
		_entries.Remove(key);
		_bytes -= entry.Size;
	}

	private void RemoveFirstToExpire()
	{
		(TKey Key, Entry Entry)? first = null;

		foreach (KeyValuePair<TKey, Entry> pair in _entries)
		{
			if (first is not { } current || pair.Value.Expires < current.Entry.Expires)
			{
				first = (pair.Key, pair.Value);
			}
		}

		if (first is { } oldest)
		{
			Remove(oldest.Key, oldest.Entry);
		}
	}

	private sealed record Entry(TValue Value, int Size, DateTimeOffset Expires);
}
