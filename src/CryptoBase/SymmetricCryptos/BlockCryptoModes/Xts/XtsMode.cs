using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Xts;

public sealed class XtsMode : BlockCryptoBase, IBlockCryptoMode
{
	public IBlockCrypto InternalBlockCrypto { get; init; }

	public ReadOnlyMemory<byte> Iv { get; init; }

	public override string Name => InternalBlockCrypto.Name + @"-XTS";

	public override int BlockSize => 16;

	private readonly IBlockCrypto _tweakCrypto;

	public XtsMode(IBlockCrypto dataCrypto, IBlockCrypto tweakCrypto, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataCrypto.BlockSize, BlockSize, nameof(dataCrypto));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakCrypto.BlockSize, BlockSize, nameof(tweakCrypto));
		ArgumentOutOfRangeException.ThrowIfLessThan(iv.Length, BlockSize, nameof(iv));

		InternalBlockCrypto = dataCrypto;
		_tweakCrypto = tweakCrypto;
		Iv = iv.Slice(0, BlockSize).ToArray();
	}

	[SkipLocalsInit]
	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		ReadOnlySpan<byte> iv = Iv.Span;
		Span<byte> tweak = stackalloc byte[BlockSize];
		_tweakCrypto.Encrypt(iv, tweak);
		IBlockCrypto crypto = InternalBlockCrypto;

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		byte[] rentedArray = ArrayPool<byte>.Shared.Rent(size);

		try
		{
			Span<byte> tweakBuffer = rentedArray.AsSpan(0, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				crypto.Encrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(rentedArray);
		}

		if (left is not 0)
		{
			Span<byte> lastDSt = destination.Slice(size - BlockSize, BlockSize);

			lastDSt.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDSt);

			FastUtils.Xor16(lastDSt, tweak);
			crypto.Encrypt(lastDSt, lastDSt);
			FastUtils.Xor16(lastDSt, tweak);
		}
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		throw new NotImplementedException();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul(ref Span<byte> buffer)
	{
		ref ulong v0 = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(buffer));
		ref ulong v1 = ref Unsafe.As<byte, ulong>(ref buffer.GetRef(8));

		ulong t = (ulong)((long)v1 >> 63 & 0x87);

		v1 = v1 << 1 | v0 >> 63;
		v0 = v0 << 1 ^ t;
	}

	public override void Reset()
	{
		InternalBlockCrypto.Reset();
		_tweakCrypto.Reset();
	}

	public override void Dispose()
	{
		InternalBlockCrypto.Dispose();
		_tweakCrypto.Dispose();
	}
}
