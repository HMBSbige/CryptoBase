namespace CryptoBase.Digests;

/// <summary>
/// Provides a base for digest implementations backed by <see cref="IncrementalHash"/>.
/// </summary>
/// <param name="name">The hash algorithm to use.</param>
public abstract class DefaultDigest(HashAlgorithmName name) : IHash
{
	/// <inheritdoc />
	public abstract string Name { get; }

	/// <inheritdoc />
	public int Length => _hasher.HashLengthInBytes;

	/// <inheritdoc />
	public abstract int BlockSize { get; }

	private readonly IncrementalHash _hasher = IncrementalHash.CreateHash(name);

	/// <inheritdoc />
	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		_hasher.AppendData(origin);
		_hasher.GetHashAndReset(destination);
	}

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> source)
	{
		_hasher.AppendData(source);
	}

	/// <inheritdoc />
	public void GetHash(Span<byte> destination)
	{
		_hasher.GetHashAndReset(destination);
	}

	/// <inheritdoc />
	public void Reset()
	{
		Span<byte> destination = stackalloc byte[Length];
		GetHash(destination);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_hasher.Dispose();
		GC.SuppressFinalize(this);
	}
}
