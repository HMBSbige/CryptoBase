namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class StreamCryptoBase : IStreamCrypto
{
	public abstract string Name { get; }

	public virtual void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));
	}

	public abstract void Reset();

	public virtual void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
