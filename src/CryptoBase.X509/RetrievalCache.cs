using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.X509;

// What a validator keeps of what it retrieved, so that a validation need not retrieve it again: issuers and CRLs by URL and the issuer of the certificate that named it, and OCSP responses by CertID. Each holds only what has been verified, so that nobody can fill it or hide the real data behind a bad copy.
internal sealed class RetrievalCaches
{
	public RetrievalCache<string, RetrievedIssuers> Issuers { get; } = new(256, 16L << 20, StringComparer.Ordinal);

	public RetrievalCache<string, CertificateRevocationList> Crls { get; } = new(64, 64L << 20, StringComparer.Ordinal);

	public RetrievalCache<ReadOnlyMemory<byte>, OcspResponse> OcspResponses { get; } = new(4096, 32L << 20, ByteMemoryComparer.Instance);
}

internal sealed record RetrievedIssuers(string Key, Certificate[] Certificates, int Size);

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
