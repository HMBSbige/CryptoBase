namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class BlockCrypto16 : IBlockCrypto
{
	public abstract string Name { get; }

	public int BlockSize => 16;

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

	public virtual void Encrypt32(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt16(source.Slice(0 * 16 * BlockSize), destination.Slice(0 * 16 * BlockSize));
		Encrypt16(source.Slice(1 * 16 * BlockSize), destination.Slice(1 * 16 * BlockSize));
	}

	public virtual void Decrypt32(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt16(source.Slice(0 * 16 * BlockSize), destination.Slice(0 * 16 * BlockSize));
		Decrypt16(source.Slice(1 * 16 * BlockSize), destination.Slice(1 * 16 * BlockSize));
	}

	public virtual void Encrypt64(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Encrypt32(source.Slice(0 * 32 * BlockSize), destination.Slice(0 * 32 * BlockSize));
		Encrypt32(source.Slice(1 * 32 * BlockSize), destination.Slice(1 * 32 * BlockSize));
	}

	public virtual void Decrypt64(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Decrypt32(source.Slice(0 * 32 * BlockSize), destination.Slice(0 * 32 * BlockSize));
		Decrypt32(source.Slice(1 * 32 * BlockSize), destination.Slice(1 * 32 * BlockSize));
	}

	public virtual void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
