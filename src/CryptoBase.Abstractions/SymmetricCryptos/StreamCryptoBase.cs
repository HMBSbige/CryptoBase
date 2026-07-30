namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Provides a base class for stateful stream encryption and decryption.
/// </summary>
public abstract class StreamCryptoBase : IStreamCrypto
{
	/// <inheritdoc />
	public abstract string Name { get; }

	/// <inheritdoc />
	public virtual void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));
	}

	/// <inheritdoc />
	public abstract void Reset();

	/// <inheritdoc />
	public virtual void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
