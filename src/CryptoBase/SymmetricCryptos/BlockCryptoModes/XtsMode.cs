namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode<TBlockCipher>(TBlockCipher dataCipher, TBlockCipher tweakCipher, bool disposeCipher = true) : IBlockModeOneShot
	where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public string Name => dataCipher.Name + @"-XTS";

	public int BlockSize => BlockBytesSize;

	private const int BlockBytesSize = 16;

	public void Dispose()
	{
		if (disposeCipher)
		{
			dataCipher.Dispose();
			tweakCipher.Dispose();
		}
	}

	public int GetMaxByteCount(int inputLength)
	{
		return inputLength;
	}

	public void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockBytesSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockBytesSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		VectorBuffer16 tweak = tweakCipher.Encrypt(iv.AsVectorBuffer16());

		int left = source.Length % BlockBytesSize;
		int size = source.Length - left;

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * BlockBytesSize
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512)
				)
			{
				int o = Encrypt32Avx512(ref tweak.V128, source, destination);

				offset += o;
				length -= o;
			}

			if (length >= 16 * BlockBytesSize
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512)
				)
			{
				int o = Encrypt16Avx512(ref tweak.V128, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported && TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
		{
			if (length >= 8 * BlockBytesSize)
			{
				int o = Encrypt8Avx2(ref tweak.V128, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * BlockBytesSize)
		{
			int o = Encrypt8(ref tweak, source.Slice(offset), destination.Slice(offset));

			offset += o;
			length -= o;
		}

		while (length > 0)
		{
			ref readonly byte sourceRef = ref source.GetReference();
			ref byte destinationRef = ref destination.GetReference();

			VectorBuffer16 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer16();
			ref VectorBuffer16 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer16();

			VectorBuffer16 tmp = src ^ tweak;
			tmp = dataCipher.Encrypt(tmp);
			dst = tmp ^ tweak;

			Gf128Mul(ref tweak);

			offset += BlockBytesSize;
			length -= BlockBytesSize;
		}

		if (left is not 0)
		{
			Span<byte> lastDst = destination.Slice(size - BlockBytesSize, BlockBytesSize);

			lastDst.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDst);

			VectorBuffer16 tmp = lastDst.AsVectorBuffer16();
			tmp ^= tweak;
			tmp = dataCipher.Encrypt(tmp);
			lastDst.AsVectorBuffer16() = tmp ^ tweak;
		}
	}

	public void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockBytesSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockBytesSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		VectorBuffer16 tweak = tweakCipher.Encrypt(iv.AsVectorBuffer16());

		int left = source.Length % BlockBytesSize;
		int size = source.Length - left - (BlockBytesSize & (left | -left) >> 31);

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * BlockBytesSize
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512)
				)
			{
				int o = Decrypt32Avx512(ref tweak.V128, source, destination);

				offset += o;
				length -= o;
			}

			if (length >= 16 * BlockBytesSize
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512)
				)
			{
				int o = Decrypt16Avx512(ref tweak.V128, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported && TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
		{
			if (length >= 8 * BlockBytesSize)
			{
				int o = Decrypt8Avx2(ref tweak.V128, source.Slice(offset), destination.Slice(offset));

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * BlockBytesSize)
		{
			int o = Decrypt8(ref tweak, source.Slice(offset), destination.Slice(offset));

			offset += o;
			length -= o;
		}

		while (length > 0)
		{
			ref readonly byte sourceRef = ref source.GetReference();
			ref byte destinationRef = ref destination.GetReference();

			VectorBuffer16 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer16();
			ref VectorBuffer16 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer16();

			VectorBuffer16 tmp = src ^ tweak;
			tmp = dataCipher.Decrypt(tmp);
			dst = tmp ^ tweak;

			Gf128Mul(ref tweak);

			offset += BlockBytesSize;
			length -= BlockBytesSize;
		}

		if (left is not 0)
		{
			VectorBuffer16 finalTweak = tweak;
			Gf128Mul(ref finalTweak);

			ReadOnlySpan<byte> lastSrc = source.Slice(size);
			Span<byte> lastDst = destination.Slice(size);

			VectorBuffer16 tmp = lastSrc.AsVectorBuffer16() ^ finalTweak;
			tmp = dataCipher.Decrypt(tmp);
			lastDst.AsVectorBuffer16() = tmp ^ finalTweak;

			lastDst.Slice(0, left).CopyTo(lastDst.Slice(BlockSize));
			lastSrc.Slice(BlockSize, left).CopyTo(lastDst);

			tmp = lastDst.AsVectorBuffer16() ^ tweak;
			tmp = dataCipher.Decrypt(tmp);
			lastDst.AsVectorBuffer16() = tmp ^ tweak;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul(ref VectorBuffer16 tweak)
	{
		if (Sse2.IsSupported)
		{
			tweak.V128 = Gf128MulSse2(tweak.V128, 1);
		}
		else
		{
			ref Int128 i = ref tweak.I128;

			i = i << 1 ^ i >> 127 & 0x87;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Gf128MulSse2(Vector128<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
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

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt8(ref VectorBuffer16 tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Unsafe.SkipInit(out VectorBuffer128 tweakBuffer);

		while (length >= 8 * BlockBytesSize)
		{
			tweakBuffer.V128_0 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_1 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_2 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_3 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_4 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_5 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_6 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_7 = tweak.V128;
			Gf128Mul(ref tweak);

			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128();

			VectorBuffer128 tmp = new()
			{
				V128_0 = src.V128_0 ^ tweakBuffer.V128_0,
				V128_1 = src.V128_1 ^ tweakBuffer.V128_1,
				V128_2 = src.V128_2 ^ tweakBuffer.V128_2,
				V128_3 = src.V128_3 ^ tweakBuffer.V128_3,
				V128_4 = src.V128_4 ^ tweakBuffer.V128_4,
				V128_5 = src.V128_5 ^ tweakBuffer.V128_5,
				V128_6 = src.V128_6 ^ tweakBuffer.V128_6,
				V128_7 = src.V128_7 ^ tweakBuffer.V128_7
			};
			tmp = dataCipher.Encrypt(tmp);
			dst = new VectorBuffer128
			{
				V128_0 = tmp.V128_0 ^ tweakBuffer.V128_0,
				V128_1 = tmp.V128_1 ^ tweakBuffer.V128_1,
				V128_2 = tmp.V128_2 ^ tweakBuffer.V128_2,
				V128_3 = tmp.V128_3 ^ tweakBuffer.V128_3,
				V128_4 = tmp.V128_4 ^ tweakBuffer.V128_4,
				V128_5 = tmp.V128_5 ^ tweakBuffer.V128_5,
				V128_6 = tmp.V128_6 ^ tweakBuffer.V128_6,
				V128_7 = tmp.V128_7 ^ tweakBuffer.V128_7
			};

			offset += 8 * BlockBytesSize;
			length -= 8 * BlockBytesSize;
		}

		return offset;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt8(ref VectorBuffer16 tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Unsafe.SkipInit(out VectorBuffer128 tweakBuffer);

		while (length >= 8 * BlockBytesSize)
		{
			tweakBuffer.V128_0 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_1 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_2 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_3 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_4 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_5 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_6 = tweak.V128;
			Gf128Mul(ref tweak);
			tweakBuffer.V128_7 = tweak.V128;
			Gf128Mul(ref tweak);

			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128();

			VectorBuffer128 tmp = new()
			{
				V128_0 = src.V128_0 ^ tweakBuffer.V128_0,
				V128_1 = src.V128_1 ^ tweakBuffer.V128_1,
				V128_2 = src.V128_2 ^ tweakBuffer.V128_2,
				V128_3 = src.V128_3 ^ tweakBuffer.V128_3,
				V128_4 = src.V128_4 ^ tweakBuffer.V128_4,
				V128_5 = src.V128_5 ^ tweakBuffer.V128_5,
				V128_6 = src.V128_6 ^ tweakBuffer.V128_6,
				V128_7 = src.V128_7 ^ tweakBuffer.V128_7
			};
			tmp = dataCipher.Decrypt(tmp);
			dst = new VectorBuffer128
			{
				V128_0 = tmp.V128_0 ^ tweakBuffer.V128_0,
				V128_1 = tmp.V128_1 ^ tweakBuffer.V128_1,
				V128_2 = tmp.V128_2 ^ tweakBuffer.V128_2,
				V128_3 = tmp.V128_3 ^ tweakBuffer.V128_3,
				V128_4 = tmp.V128_4 ^ tweakBuffer.V128_4,
				V128_5 = tmp.V128_5 ^ tweakBuffer.V128_5,
				V128_6 = tmp.V128_6 ^ tweakBuffer.V128_6,
				V128_7 = tmp.V128_7 ^ tweakBuffer.V128_7
			};

			offset += 8 * BlockBytesSize;
			length -= 8 * BlockBytesSize;
		}

		return offset;
	}
}

public static class XtsMode
{
	public static void GetIv(in Span<byte> iv, in UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}
}
