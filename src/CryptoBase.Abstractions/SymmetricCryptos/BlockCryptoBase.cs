namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class BlockCryptoBase : IBlockCrypto
{
	public abstract string Name { get; }

	public abstract int BlockSize { get; }

	public virtual BlockCryptoHardwareAcceleration HardwareAcceleration => BlockCryptoHardwareAcceleration.Unknown;

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

	public virtual void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt(source.Slice(0 * 1 * BlockSize), destination.Slice(0 * 1 * BlockSize));
		Encrypt(source.Slice(1 * 1 * BlockSize), destination.Slice(1 * 1 * BlockSize));
	}

	public virtual void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt(source.Slice(0 * 1 * BlockSize), destination.Slice(0 * 1 * BlockSize));
		Decrypt(source.Slice(1 * 1 * BlockSize), destination.Slice(1 * 1 * BlockSize));
	}

	public virtual void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt2(source.Slice(0 * 2 * BlockSize), destination.Slice(0 * 2 * BlockSize));
		Encrypt2(source.Slice(1 * 2 * BlockSize), destination.Slice(1 * 2 * BlockSize));
	}

	public virtual void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt2(source.Slice(0 * 2 * BlockSize), destination.Slice(0 * 2 * BlockSize));
		Decrypt2(source.Slice(1 * 2 * BlockSize), destination.Slice(1 * 2 * BlockSize));
	}

	public virtual void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt4(source.Slice(0 * 4 * BlockSize), destination.Slice(0 * 4 * BlockSize));
		Encrypt4(source.Slice(1 * 4 * BlockSize), destination.Slice(1 * 4 * BlockSize));
	}

	public virtual void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt4(source.Slice(0 * 4 * BlockSize), destination.Slice(0 * 4 * BlockSize));
		Decrypt4(source.Slice(1 * 4 * BlockSize), destination.Slice(1 * 4 * BlockSize));
	}

	public virtual void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt8(source.Slice(0 * 8 * BlockSize), destination.Slice(0 * 8 * BlockSize));
		Encrypt8(source.Slice(1 * 8 * BlockSize), destination.Slice(1 * 8 * BlockSize));
	}

	public virtual void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt8(source.Slice(0 * 8 * BlockSize), destination.Slice(0 * 8 * BlockSize));
		Decrypt8(source.Slice(1 * 8 * BlockSize), destination.Slice(1 * 8 * BlockSize));
	}

	public virtual void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
