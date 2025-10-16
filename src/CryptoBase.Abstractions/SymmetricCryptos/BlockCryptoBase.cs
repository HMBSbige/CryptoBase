namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class BlockCryptoBase : IBlockCrypto
{
	public abstract string Name { get; }

	public abstract int BlockSize { get; }

	public virtual void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));
	}

	public virtual void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));
	}

	public virtual void Reset() { }

	public virtual void Dispose() { }
}
