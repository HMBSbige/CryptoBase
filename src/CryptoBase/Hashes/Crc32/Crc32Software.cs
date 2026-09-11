namespace CryptoBase.Hashes.Crc32;

internal static class Crc32Software
{
	private const int TableSize = Crc32SoftwareTables.TableSize;
	private const int FourWayBraidBlockSizeInBytes = Crc32SoftwareTables.FourWayBraidBlockSizeInBytes;

	private const int FiveWayBraidBlockSizeInBytes = Crc32SoftwareTables.FiveWayBraidBlockSizeInBytes;

	// Four lanes reduce x64 register pressure on small inputs; five lanes hide lookup latency on larger inputs.
	private const int X64FiveWayBraidThresholdInBytes = 1280;

	private static bool IsX64Process { get; } = RuntimeInformation.ProcessArchitecture is Architecture.X64;

	private static bool UseX64Braid => X86Base.X64.IsSupported || !ArmBase.Arm64.IsSupported && IsX64Process;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint Update<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		ref Crc32TableSet tables = ref Crc32SoftwareTables.Get<TAlgorithm>();

		if (UseX64Braid)
		{
			return UpdateX64(state, source, ref tables.Lookup[0], ref tables.SlicingLookup[0], ref tables.FourWayBraidLookup[0], ref tables.FiveWayBraidLookup[0]);
		}

		return UpdateFiveWay(state, source, ref tables.Lookup[0], ref tables.SlicingLookup[0], ref tables.FiveWayBraidLookup[0]);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateX64(uint state, ReadOnlySpan<byte> source, ref uint lookup, ref uint slicingLookup, ref uint fourWayBraidLookup, ref uint fiveWayBraidLookup)
	{
		if (source.Length >= FourWayBraidBlockSizeInBytes)
		{
			return source.Length >= X64FiveWayBraidThresholdInBytes
				? UpdateSlicing<X64FiveWayBraid>(state, source, ref lookup, ref slicingLookup, ref fiveWayBraidLookup)
				: UpdateSlicing<FourWayBraid>(state, source, ref lookup, ref slicingLookup, ref fourWayBraidLookup);
		}

		return UpdateBytes(state, source, ref lookup);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateFiveWay(uint state, ReadOnlySpan<byte> source, ref uint lookup, ref uint slicingLookup, ref uint braidLookup)
	{
		return source.Length >= FiveWayBraidBlockSizeInBytes
			? UpdateSlicing<FiveWayBraid>(state, source, ref lookup, ref slicingLookup, ref braidLookup)
			: UpdateBytes(state, source, ref lookup);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateBytes(uint state, ReadOnlySpan<byte> source, ref uint lookup)
	{
		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;

		while (length >= sizeof(ulong))
		{
			state = UpdateByte(state, sourceRef, ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 1), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 2), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 3), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 4), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 5), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 6), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 7), ref lookup);
			sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(ulong));
			length -= sizeof(ulong);
		}

		if ((length & sizeof(uint)) is not 0)
		{
			state = UpdateByte(state, sourceRef, ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 1), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 2), ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 3), ref lookup);
			sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(uint));
		}

		if ((length & sizeof(ushort)) is not 0)
		{
			state = UpdateByte(state, sourceRef, ref lookup);
			state = UpdateByte(state, Unsafe.Add(ref sourceRef, 1), ref lookup);
			sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(ushort));
		}

		if ((length & 1) is not 0)
		{
			state = UpdateByte(state, sourceRef, ref lookup);
		}

		return state;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static uint UpdateSlicing<TMode>(uint state, ReadOnlySpan<byte> source, ref uint lookup, ref uint slicingLookup, ref uint braidLookup)
	{
		bool useFourWayBraid = typeof(TMode) == typeof(FourWayBraid);
		int braidBlockSize = useFourWayBraid ? FourWayBraidBlockSizeInBytes : FiveWayBraidBlockSizeInBytes;
		Debug.Assert(source.Length >= braidBlockSize);

		ref byte sourceRef = ref source.GetReference();
		ref uint braidLookup1 = ref Unsafe.Add(ref braidLookup, 1 * TableSize);
		ref uint braidLookup2 = ref Unsafe.Add(ref braidLookup, 2 * TableSize);
		ref uint braidLookup3 = ref Unsafe.Add(ref braidLookup, 3 * TableSize);
		ref uint braidLookup4 = ref Unsafe.Add(ref braidLookup, 4 * TableSize);
		ref uint braidLookup5 = ref Unsafe.Add(ref braidLookup, 5 * TableSize);
		ref uint braidLookup6 = ref Unsafe.Add(ref braidLookup, 6 * TableSize);
		ref uint braidLookup7 = ref Unsafe.Add(ref braidLookup, 7 * TableSize);
		int length = source.Length;

		if (length >= 2 * braidBlockSize)
		{
			int blockCount = length / braidBlockSize;
			int braidedLength = blockCount * braidBlockSize;
			ulong crc0 = state;
			ulong crc1 = 0;
			ulong crc2 = 0;
			ulong crc3 = 0;
			ulong crc4 = 0;

			for (int block = 1; block < blockCount; ++block)
			{
				ulong word0 = ReadWord(ref sourceRef) ^ crc0;
				ulong word1 = ReadWord(ref Unsafe.Add(ref sourceRef, 8)) ^ crc1;
				ulong word2 = ReadWord(ref Unsafe.Add(ref sourceRef, 16)) ^ crc2;
				ulong word3 = ReadWord(ref Unsafe.Add(ref sourceRef, 24)) ^ crc3;
				ulong word4 = useFourWayBraid ? 0 : ReadWord(ref Unsafe.Add(ref sourceRef, 32)) ^ crc4;
				crc0 = Unsafe.Add(ref braidLookup, (byte)word0);
				crc1 = Unsafe.Add(ref braidLookup, (byte)word1);
				crc2 = Unsafe.Add(ref braidLookup, (byte)word2);
				crc3 = Unsafe.Add(ref braidLookup, (byte)word3);

				if (!useFourWayBraid)
				{
					crc4 = Unsafe.Add(ref braidLookup, (byte)word4);
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup1, (byte)(word0 >> 8), 1 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup1, (byte)(word1 >> 8), 1 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup1, (byte)(word2 >> 8), 1 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup1, (byte)(word3 >> 8), 1 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup1, (byte)(word4 >> 8), 1 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup2, (byte)(word0 >> 16), 2 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup2, (byte)(word1 >> 16), 2 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup2, (byte)(word2 >> 16), 2 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup2, (byte)(word3 >> 16), 2 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup2, (byte)(word4 >> 16), 2 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup3, (int)word0 >>> 24, 3 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup3, (int)word1 >>> 24, 3 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup3, (int)word2 >>> 24, 3 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup3, (int)word3 >>> 24, 3 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup3, (int)word4 >>> 24, 3 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup4, (byte)(word0 >> 32), 4 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup4, (byte)(word1 >> 32), 4 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup4, (byte)(word2 >> 32), 4 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup4, (byte)(word3 >> 32), 4 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup4, (byte)(word4 >> 32), 4 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup5, (byte)(word0 >> 40), 5 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup5, (byte)(word1 >> 40), 5 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup5, (byte)(word2 >> 40), 5 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup5, (byte)(word3 >> 40), 5 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup5, (byte)(word4 >> 40), 5 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup6, (byte)(word0 >> 48), 6 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup6, (byte)(word1 >> 48), 6 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup6, (byte)(word2 >> 48), 6 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup6, (byte)(word3 >> 48), 6 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup6, (byte)(word4 >> 48), 6 * TableSize * sizeof(uint));
				}

				crc0 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup7, (int)(word0 >> 56), 7 * TableSize * sizeof(uint));
				crc1 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup7, (int)(word1 >> 56), 7 * TableSize * sizeof(uint));
				crc2 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup7, (int)(word2 >> 56), 7 * TableSize * sizeof(uint));
				crc3 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup7, (int)(word3 >> 56), 7 * TableSize * sizeof(uint));

				if (!useFourWayBraid)
				{
					crc4 ^= GetBraidLookup<TMode>(ref braidLookup, ref braidLookup7, (int)(word4 >> 56), 7 * TableSize * sizeof(uint));
				}

				sourceRef = ref Unsafe.Add(ref sourceRef, braidBlockSize);
			}

			uint combined = UpdateWord(ReadWord(ref sourceRef) ^ crc0, ref lookup, ref slicingLookup);
			combined = UpdateWord(ReadWord(ref Unsafe.Add(ref sourceRef, 8)) ^ crc1 ^ combined, ref lookup, ref slicingLookup);
			combined = UpdateWord(ReadWord(ref Unsafe.Add(ref sourceRef, 16)) ^ crc2 ^ combined, ref lookup, ref slicingLookup);

			if (useFourWayBraid)
			{
				state = UpdateWord(ReadWord(ref Unsafe.Add(ref sourceRef, 24)) ^ crc3 ^ combined, ref lookup, ref slicingLookup);
			}
			else
			{
				combined = UpdateWord(ReadWord(ref Unsafe.Add(ref sourceRef, 24)) ^ crc3 ^ combined, ref lookup, ref slicingLookup);
				state = UpdateWord(ReadWord(ref Unsafe.Add(ref sourceRef, 32)) ^ crc4 ^ combined, ref lookup, ref slicingLookup);
			}

			sourceRef = ref Unsafe.Add(ref sourceRef, braidBlockSize);
			length -= braidedLength;
		}

		while (length >= sizeof(ulong))
		{
			state = UpdateWord(ReadWord(ref sourceRef) ^ state, ref lookup, ref slicingLookup);
			sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(ulong));
			length -= sizeof(ulong);
		}

		while (length > 0)
		{
			state = UpdateByte(state, sourceRef, ref lookup);
			sourceRef = ref Unsafe.Add(ref sourceRef, 1);
			--length;
		}

		return state;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GetBraidLookup<TMode>(ref uint baseLookup, ref uint tableLookup, byte index, nuint byteOffset)
	{
		return typeof(TMode) != typeof(FiveWayBraid)
			? Unsafe.AddByteOffset(ref Unsafe.Add(ref baseLookup, index), byteOffset)
			: Unsafe.Add(ref tableLookup, index);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GetBraidLookup<TMode>(ref uint baseLookup, ref uint tableLookup, int index, nuint byteOffset)
	{
		return typeof(TMode) != typeof(FiveWayBraid)
			? Unsafe.AddByteOffset(ref Unsafe.Add(ref baseLookup, index), byteOffset)
			: Unsafe.Add(ref tableLookup, index);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ReadWord(ref byte source)
	{
		ulong value = Unsafe.ReadUnaligned<ulong>(ref source);
		return BitConverter.IsLittleEndian ? value : BinaryPrimitives.ReverseEndianness(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateWord(ulong word, ref uint lookup, ref uint slicingLookup)
	{
		return Unsafe.Add(ref slicingLookup, 6 * TableSize + (byte)word)
				^ Unsafe.Add(ref slicingLookup, 5 * TableSize + (byte)(word >> 8))
				^ Unsafe.Add(ref slicingLookup, 4 * TableSize + (byte)(word >> 16))
				^ Unsafe.Add(ref slicingLookup, 3 * TableSize + ((int)word >>> 24))
				^ Unsafe.Add(ref slicingLookup, 2 * TableSize + (byte)(word >> 32))
				^ Unsafe.Add(ref slicingLookup, 1 * TableSize + (byte)(word >> 40))
				^ Unsafe.Add(ref slicingLookup, (byte)(word >> 48))
				^ Unsafe.Add(ref lookup, (int)(word >> 56));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateByte(uint state, byte value, ref uint lookup)
	{
		return Unsafe.Add(ref lookup, (byte)(state ^ value)) ^ state >> 8;
	}

	private readonly struct FourWayBraid;

	private readonly struct FiveWayBraid;

	private readonly struct X64FiveWayBraid;
}
