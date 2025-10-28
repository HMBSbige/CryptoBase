namespace CryptoBase.Digests;

public abstract class DefaultDigest : IHash
{
	public abstract string Name { get; }
	public int Length => _hasher.HashLengthInBytes;
	public abstract int BlockSize { get; }

	private readonly IncrementalHash _hasher;

	protected DefaultDigest(HashAlgorithmName name)
	{
		_hasher = IncrementalHash.CreateHash(name);
	}

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		_hasher.AppendData(origin);
		_hasher.GetHashAndReset(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		_hasher.AppendData(source);
	}

	public void GetHash(Span<byte> destination)
	{
		_hasher.GetHashAndReset(destination);
	}

	public void Reset()
	{
		Span<byte> destination = stackalloc byte[Length];
		GetHash(destination);
	}

	public void Dispose()
	{
		_hasher.Dispose();
		GC.SuppressFinalize(this);
	}
}
