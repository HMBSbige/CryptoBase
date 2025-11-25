namespace CryptoBase.Abstractions.SymmetricCryptos;

public abstract class BlockCrypto16 : IBlockCrypto16
{
	public abstract string Name { get; }

	public int BlockSize => 16;

	public virtual BlockCryptoHardwareAcceleration HardwareAcceleration => BlockCryptoHardwareAcceleration.Unknown;

	public abstract VectorBuffer16 Encrypt(VectorBuffer16 source);
	public abstract VectorBuffer16 Decrypt(VectorBuffer16 source);

	public virtual VectorBuffer32 Encrypt(VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer32 Decrypt(VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer64 Encrypt(VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer64 Decrypt(VectorBuffer64 source)
	{
		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer128 Encrypt(VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer128 Decrypt(VectorBuffer128 source)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer256 Encrypt(VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer256 Decrypt(VectorBuffer256 source)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer512 Encrypt(VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer512 Decrypt(VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer1024 Encrypt(VectorBuffer1024 source)
	{
		Unsafe.SkipInit(out VectorBuffer1024 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	public virtual VectorBuffer1024 Decrypt(VectorBuffer1024 source)
	{
		Unsafe.SkipInit(out VectorBuffer1024 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	public void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer16()));
	}

	public void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer16()));
	}

	public virtual void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer32()));
	}

	public virtual void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer32()));
	}

	public virtual void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer64()));
	}

	public virtual void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer64()));
	}

	public virtual void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer128()));
	}

	public virtual void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer128()));
	}

	public virtual void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer256()));
	}

	public virtual void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer256()));
	}

	public virtual void Encrypt32(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 32 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 32 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Encrypt(source.AsVectorBuffer512()));
	}

	public virtual void Decrypt32(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 32 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 32 * BlockSize, nameof(destination));

		Unsafe.WriteUnaligned(ref destination.GetReference(), Decrypt(source.AsVectorBuffer512()));
	}

	public virtual void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
