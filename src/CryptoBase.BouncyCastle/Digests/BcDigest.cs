using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;

namespace CryptoBase.BouncyCastle.Digests;

public abstract class BcDigest(IDigest hasher) : IHash
{
	public abstract string Name { get; }

	public int Length => hasher.GetDigestSize();

	public int BlockSize => hasher.GetByteLength();

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		hasher.BlockUpdate(source);
	}

	public void GetHash(Span<byte> destination)
	{
		hasher.DoFinal(destination);
	}

	public void Reset()
	{
		hasher.Reset();
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
