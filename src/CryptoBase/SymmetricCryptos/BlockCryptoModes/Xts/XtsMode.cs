using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Xts;

public sealed class XtsMode : IBlockModeOneShot
{
	public int BlockSize => 16;

	private readonly IBlockCrypto _dataCrypto;
	private readonly IBlockCrypto _tweakCrypto;

	public XtsMode(IBlockCrypto dataCrypto, IBlockCrypto tweakCrypto)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataCrypto.BlockSize, BlockSize, nameof(dataCrypto));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakCrypto.BlockSize, BlockSize, nameof(tweakCrypto));

		_dataCrypto = dataCrypto;
		_tweakCrypto = tweakCrypto;
	}

	[SkipLocalsInit]
	public void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		using CryptoBuffer<byte> cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);
		IBlockCrypto crypto = _dataCrypto;

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		using (CryptoBuffer<byte> buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

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

	[SkipLocalsInit]
	public void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		using CryptoBuffer<byte> cryptoBuffer = new(stackalloc byte[BlockSize]);
		Span<byte> tweak = cryptoBuffer.Span;
		_tweakCrypto.Encrypt(iv, tweak);
		IBlockCrypto crypto = _dataCrypto;

		int left = source.Length % BlockSize;
		int size = source.Length - left - (BlockSize & (left | -left) >> 31);

		using (CryptoBuffer<byte> buffer = new(size))
		{
			Span<byte> tweakBuffer = buffer.Span;

			for (int i = 0; i < size; i += BlockSize)
			{
				tweak.CopyTo(tweakBuffer.Slice(i));
				Gf128Mul(ref tweak);
			}

			FastUtils.Xor(source, tweakBuffer, destination, size);

			for (int i = 0; i < size; i += BlockSize)
			{
				Span<byte> block = destination.Slice(i, BlockSize);
				crypto.Decrypt(block, block);
			}

			FastUtils.Xor(destination, tweakBuffer, size);
		}

		if (left is not 0)
		{
			using CryptoBuffer<byte> buffer = new(stackalloc byte[BlockSize]);
			Span<byte> finalTweak = buffer.Span;
			tweak.CopyTo(finalTweak);
			Gf128Mul(ref finalTweak);

			ReadOnlySpan<byte> lastSrc = source.Slice(size);
			Span<byte> lastDst = destination.Slice(size);

			FastUtils.Xor16(lastSrc, finalTweak, lastDst);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, finalTweak);

			lastDst.Slice(0, left).CopyTo(lastDst.Slice(BlockSize));
			lastSrc.Slice(BlockSize, left).CopyTo(lastDst);

			FastUtils.Xor16(lastDst, tweak);
			_dataCrypto.Decrypt(lastDst, lastDst);
			FastUtils.Xor16(lastDst, tweak);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul(ref Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref ulong v0 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref ptr, 0 * sizeof(ulong)));
		ref ulong v1 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref ptr, 1 * sizeof(ulong)));

		ulong t = (ulong)((long)v1 >> 63 & 0x87);

		v1 = v1 << 1 | v0 >> 63;
		v0 = v0 << 1 ^ t;
	}

	public static void GetIv(Span<byte> iv, UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}
}
