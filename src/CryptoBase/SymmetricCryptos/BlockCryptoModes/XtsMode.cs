namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode : IBlockModeOneShot
{
	public string Name => _dataCrypto.Name + @"-XTS";

	public int BlockSize => 16;

	private readonly IBlockCrypto16 _dataCrypto;
	private readonly IBlockCrypto16 _tweakCrypto;
	private readonly bool _disposeCrypto;

	public XtsMode(IBlockCrypto16 dataCrypto, IBlockCrypto16 tweakCrypto, bool disposeCrypto = true)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataCrypto.BlockSize, BlockSize, nameof(dataCrypto));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakCrypto.BlockSize, BlockSize, nameof(tweakCrypto));

		_dataCrypto = dataCrypto;
		_tweakCrypto = tweakCrypto;
		_disposeCrypto = disposeCrypto;
	}

	public void Dispose()
	{
		if (_disposeCrypto)
		{
			_dataCrypto.Dispose();
			_tweakCrypto.Dispose();
		}
	}

	public int GetMaxByteCount(int inputLength)
	{
		return inputLength;
	}

	public static void GetIv(in Span<byte> iv, in UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
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

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * BlockSize)
			{
				int o = Encrypt32Avx512(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}

			if (length >= 16 * BlockSize)
			{
				int o = Encrypt16Avx512(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
		{
			if (length >= 8 * BlockSize)
			{
				int o = Encrypt8Avx2(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * BlockSize)
		{
			const int blockSize = 8 * 16;
			using CryptoBuffer<byte> buffer = new(blockSize);
			Span<byte> tweakBuffer = buffer.Span;

			while (length >= 8 * BlockSize)
			{
				ReadOnlySpan<byte> src = source.Slice(offset, blockSize);
				Span<byte> dst = destination.Slice(offset, blockSize);

				for (int i = 0; i < blockSize; i += BlockSize)
				{
					tweak.CopyTo(tweakBuffer.Slice(i));
					Gf128Mul(tweak);
				}

				FastUtils.Xor(src, tweakBuffer, dst, blockSize);
				_dataCrypto.Encrypt8(dst, dst);
				FastUtils.Xor(dst, tweakBuffer, blockSize);

				offset += blockSize;
				length -= blockSize;
			}
		}

		while (length > 0)
		{
			ReadOnlySpan<byte> src = source.Slice(offset, BlockSize);
			Span<byte> dst = destination.Slice(offset, BlockSize);

			FastUtils.Xor16(src, tweak, dst);
			_dataCrypto.Encrypt(dst, dst);
			FastUtils.Xor16(dst, tweak);

			Gf128Mul(tweak);

			offset += BlockSize;
			length -= BlockSize;
		}

		if (left is not 0)
		{
			Span<byte> lastDSt = destination.Slice(size - BlockSize, BlockSize);

			lastDSt.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDSt);

			FastUtils.Xor16(lastDSt, tweak);
			_dataCrypto.Encrypt(lastDSt, lastDSt);
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

		int left = source.Length % BlockSize;
		int size = source.Length - left - (BlockSize & (left | -left) >> 31);

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * BlockSize)
			{
				int o = Decrypt32Avx512(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}

			if (length >= 16 * BlockSize)
			{
				int o = Decrypt16Avx512(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
		{
			if (length >= 8 * BlockSize)
			{
				int o = Decrypt8Avx2(tweak, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * BlockSize)
		{
			const int blockSize = 8 * 16;
			using CryptoBuffer<byte> buffer = new(blockSize);
			Span<byte> tweakBuffer = buffer.Span;

			while (length >= 8 * BlockSize)
			{
				ReadOnlySpan<byte> src = source.Slice(offset, blockSize);
				Span<byte> dst = destination.Slice(offset, blockSize);

				for (int i = 0; i < blockSize; i += BlockSize)
				{
					tweak.CopyTo(tweakBuffer.Slice(i));
					Gf128Mul(tweak);
				}

				FastUtils.Xor(src, tweakBuffer, dst, blockSize);
				_dataCrypto.Decrypt8(dst, dst);
				FastUtils.Xor(dst, tweakBuffer, blockSize);

				offset += blockSize;
				length -= blockSize;
			}
		}

		while (length > 0)
		{
			ReadOnlySpan<byte> src = source.Slice(offset, BlockSize);
			Span<byte> dst = destination.Slice(offset, BlockSize);

			FastUtils.Xor16(src, tweak, dst);
			_dataCrypto.Decrypt(dst, dst);
			FastUtils.Xor16(dst, tweak);

			Gf128Mul(tweak);

			offset += BlockSize;
			length -= BlockSize;
		}

		if (left is not 0)
		{
			using CryptoBuffer<byte> buffer = new(stackalloc byte[BlockSize]);
			Span<byte> finalTweak = buffer.Span;
			tweak.CopyTo(finalTweak);
			Gf128Mul(finalTweak);

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
	private static void Gf128Mul(in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();

		if (Sse2.IsSupported)
		{
			ref Vector128<byte> tweak = ref Unsafe.As<byte, Vector128<byte>>(ref ptr);

			tweak = Gf128Mul(tweak);
		}
		else
		{
			ref Int128 i = ref Unsafe.As<byte, Int128>(ref ptr);

			i = i << 1 ^ i >> 127 & 0x87;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Gf128Mul(in Vector128<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x = 1)
	{
		if (x is 1)
		{
			Vector128<int> carry = Sse2.Shuffle(tweak.AsInt32(), 0b00_01_00_11) >> 31;

			return (tweak.AsUInt64() << 1).AsByte() ^ carry.AsByte() & Vector128.Create(0x87, 1).AsByte();
		}

		Vector128<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector128<ulong> tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, Vector128.Create(0x87UL), 0x01);

		tmp1 = Sse2.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}
}
