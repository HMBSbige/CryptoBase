namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	// TBL2 maps any alphabet, so built-in and custom alphabets share these kernels.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetEncodeAlphabet(byte[] alphabet, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh)
	{
		ref byte alphabetReference = ref MemoryMarshal.GetArrayDataReference(alphabet);
		alphabetLow = Vector128.LoadUnsafe(ref alphabetReference);
		alphabetHigh = Vector128.LoadUnsafe(ref alphabetReference, 16);
	}

	// Each qword holds one 40-bit group as four big-endian 16-bit windows; per-lane shifts move the even and odd symbols into the low and high bytes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeTwoAdvSimd(Vector128<byte> input, Vector128<byte> indices, Vector128<short> evenShifts, Vector128<short> oddShifts, Vector128<byte> alphabetLow, Vector128<byte> alphabetHigh)
	{
		Vector128<ushort> windows = Vector128.Shuffle(input, indices).AsUInt16();
		Vector128<ushort> even = AdvSimd.ShiftLogical(windows, evenShifts) & Vector128.Create((ushort)SymbolMask);
		Vector128<ushort> odd = AdvSimd.ShiftLogical(windows, oddShifts);
		Vector128<byte> symbols = Vector128.ConditionalSelect(Vector128.Create((ushort)(SymbolMask << 8)), odd, even).AsByte();
		return AdvSimd.Arm64.VectorTableLookup((alphabetLow, alphabetHigh), symbols);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeUtf8AdvSimd(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte[] alphabet)
	{
		GetEncodeAlphabet(alphabet, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> lowIndices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8);
		Vector128<byte> highIndices = Vector128.Create((byte)7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset, 4);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		int octCount = blockCount >> 3;

		for (int i = 0; i < octCount; ++i)
		{
			Vector128<byte> input0 = Vector128.LoadUnsafe(ref sourceReference);
			Vector128<byte> input1 = Vector128.LoadUnsafe(ref sourceReference, 4);
			Vector128<byte> input2 = Vector128.LoadUnsafe(ref sourceReference, 20);
			Vector128<byte> input3 = Vector128.LoadUnsafe(ref sourceReference, 24);
			EncodeTwoAdvSimd(input0, lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference);
			EncodeTwoAdvSimd(input1, highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, 16);
			EncodeTwoAdvSimd(input2, lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, 32);
			EncodeTwoAdvSimd(input3, highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, 48);
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}

		if ((blockCount & 4) is not 0)
		{
			EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference);
			EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, 16);
		}

		int remainder = blockCount & 3;

		if (remainder is not 0)
		{
			// Re-encode the last four whole blocks; one or two leftover blocks only need the last pair.
			int lastQuad = blockCount - 4;
			ref byte lastSource = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset + lastQuad * InputBytesPerBlock);
			ref byte lastDestination = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset + lastQuad * OutputSymbolsPerBlock);

			if (remainder is 3)
			{
				EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref lastSource), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref lastDestination);
			}

			EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref lastSource, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref lastDestination, 16);
		}

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeCharsAdvSimd(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte[] alphabet)
	{
		GetEncodeAlphabet(alphabet, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> lowIndices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8);
		Vector128<byte> highIndices = Vector128.Create((byte)7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset, 4);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref char destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		int octCount = blockCount >> 3;

		for (int i = 0; i < octCount; ++i)
		{
			Vector128<byte> input0 = Vector128.LoadUnsafe(ref sourceReference);
			Vector128<byte> input1 = Vector128.LoadUnsafe(ref sourceReference, 4);
			Vector128<byte> input2 = Vector128.LoadUnsafe(ref sourceReference, 20);
			Vector128<byte> input3 = Vector128.LoadUnsafe(ref sourceReference, 24);
			StoreEncodedChars(EncodeTwoAdvSimd(input0, lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref destinationReference);
			StoreEncodedChars(EncodeTwoAdvSimd(input1, highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, 16));
			StoreEncodedChars(EncodeTwoAdvSimd(input2, lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, 32));
			StoreEncodedChars(EncodeTwoAdvSimd(input3, highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, 48));
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}

		if ((blockCount & 4) is not 0)
		{
			StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref destinationReference);
			StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, 16));
		}

		int remainder = blockCount & 3;

		if (remainder is not 0)
		{
			// Re-encode the last four whole blocks; one or two leftover blocks only need the last pair.
			int lastQuad = blockCount - 4;
			ref byte lastSource = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset + lastQuad * InputBytesPerBlock);
			ref char lastDestination = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset + lastQuad * OutputSymbolsPerBlock);

			if (remainder is 3)
			{
				StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref lastSource), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref lastDestination);
			}

			StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref lastSource, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref lastDestination, 16));
		}

		return blockCount * InputBytesPerBlock;
	}

	private static int EncodeUtf8AdvSimdShort(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte[] alphabet)
	{
		GetEncodeAlphabet(alphabet, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> indices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 14, 7, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeShortBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		EncodeTwoAdvSimd(LoadTenBytes(ref sourceReference), indices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference);

		if (blockCount is 3)
		{
			EncodeTwoAdvSimd(LoadTenBytes(ref Unsafe.Add(ref sourceReference, InputBytesPerBlock)), indices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, OutputSymbolsPerBlock);
		}

		return blockCount * InputBytesPerBlock;
	}

	private static int EncodeCharsAdvSimdShort(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte[] alphabet)
	{
		GetEncodeAlphabet(alphabet, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> indices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 14, 7, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeShortBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref char destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		StoreEncodedChars(EncodeTwoAdvSimd(LoadTenBytes(ref sourceReference), indices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref destinationReference);

		if (blockCount is 3)
		{
			StoreEncodedChars(EncodeTwoAdvSimd(LoadTenBytes(ref Unsafe.Add(ref sourceReference, InputBytesPerBlock)), indices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, OutputSymbolsPerBlock));
		}

		return blockCount * InputBytesPerBlock;
	}

	private const byte AdvSimdDecodeTableStart = 0x30;
	private const byte AdvSimdDecodeValidBit = 0x20;

	// Both built-in alphabets use symbols 0x30-0x6F, so one four-register TBL maps symbol - 0x30. Entries hold the value with bit 5 set;
	// invalid symbols and the zeroes TBL returns for out-of-range indices both lack it, and the packer ignores bits above the low five.
	private static readonly byte[] AdvSimdRfcDecodeTable = CreateAdvSimdDecodeTable(Rfc4648Alphabet);
	private static readonly byte[] AdvSimdHexDecodeTable = CreateAdvSimdDecodeTable(Rfc4648HexAlphabet);

	private static byte[] CreateAdvSimdDecodeTable(string alphabet)
	{
		byte[] table = new byte[4 * Vector128<byte>.Count];

		for (int i = 0; i < alphabet.Length; ++i)
		{
			table[alphabet[i] - AdvSimdDecodeTableStart] = (byte)(i | AdvSimdDecodeValidBit);
		}

		return table;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetDecodeTable(byte alphabetKind, out Vector128<byte> table0, out Vector128<byte> table1, out Vector128<byte> table2, out Vector128<byte> table3)
	{
		ref byte table = ref MemoryMarshal.GetArrayDataReference(alphabetKind is Rfc4648HexAlphabetKind ? AdvSimdHexDecodeTable : AdvSimdRfcDecodeTable);
		table0 = Vector128.LoadUnsafe(ref table);
		table1 = Vector128.LoadUnsafe(ref table, 16);
		table2 = Vector128.LoadUnsafe(ref table, 32);
		table3 = Vector128.LoadUnsafe(ref table, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecodeTwoAdvSimd(Vector128<byte> input, Vector128<byte> table0, Vector128<byte> table1, Vector128<byte> table2, Vector128<byte> table3)
	{
		return AdvSimd.Arm64.VectorTableLookup((table0, table1, table2, table3), input - Vector128.Create(AdvSimdDecodeTableStart));
	}

	// Valid entries are 0x20-0x3F, so their AND keeps bit 5 and any invalid lane drops the minimum below it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsValidAdvSimd(Vector128<byte> values)
	{
		return AdvSimd.Arm64.MinAcross(values).ToScalar() >= AdvSimdDecodeValidBit;
	}

	// Shift-and-insert merges adjacent fields into 10-, 20- and 40-bit big-endian groups; the bits it leaves above each group are cleared
	// by the next insert or skipped by the final byte gather.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PackDecodedAdvSimd(Vector128<byte> values, Vector128<byte> extract)
	{
		Vector128<ushort> pairs = values.AsUInt16();
		pairs = AdvSimd.ShiftLeftAndInsert(pairs >>> 8, pairs, 5);
		Vector128<uint> quads = pairs.AsUInt32();
		quads = AdvSimd.ShiftLeftAndInsert(quads >>> 16, quads, 10);
		Vector128<ulong> groups = quads.AsUInt64();
		groups = AdvSimd.ShiftLeftAndInsert(groups >>> 32, groups, 20);
		return Vector128.Shuffle(groups.AsByte(), extract);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int DecodeUtf8AdvSimd(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeTable(alphabetKind, out Vector128<byte> table0, out Vector128<byte> table1, out Vector128<byte> table2, out Vector128<byte> table3);
		Vector128<byte> extract = Vector128.Create(4, 3, 2, 1, 0, 12, 11, 10, 9, 8, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int groupCount = blockCount >> 2;
		int processedBlocks = 0;

		for (int i = 0; i < groupCount; ++i)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), table0, table1, table2, table3);
			Vector128<byte> second = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 16)), table0, table1, table2, table3);
			Vector128<byte> third = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 32)), table0, table1, table2, table3);
			Vector128<byte> fourth = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 48)), table0, table1, table2, table3);

			if (!IsValidAdvSimd(first & second & third & fourth))
			{
				break;
			}

			PackDecodedAdvSimd(first, extract).StoreUnsafe(ref destinationPointer);
			PackDecodedAdvSimd(second, extract).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 10));
			PackDecodedAdvSimd(third, extract).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 20));
			StoreDecoded(PackDecodedAdvSimd(fourth, extract), ref Unsafe.Add(ref destinationPointer, 30));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 4;
		}

		if (processedBlocks == groupCount * 4 && blockCount - processedBlocks >= 2)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), table0, table1, table2, table3);
			Vector128<byte> second = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 16)), table0, table1, table2, table3);

			if (IsValidAdvSimd(first & second))
			{
				PackDecodedAdvSimd(first, extract).StoreUnsafe(ref destinationPointer);
				StoreDecoded(PackDecodedAdvSimd(second, extract), ref Unsafe.Add(ref destinationPointer, 10));
				sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
				destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
				processedBlocks += 2;
			}
		}

		if (processedBlocks == blockCount - 1)
		{
			Vector128<byte> values = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), table0, table1, table2, table3);

			if (IsValidAdvSimd(values))
			{
				StoreDecoded(PackDecodedAdvSimd(values, extract), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int DecodeCharsAdvSimd(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeTable(alphabetKind, out Vector128<byte> table0, out Vector128<byte> table1, out Vector128<byte> table2, out Vector128<byte> table3);
		Vector128<byte> extract = Vector128.Create(4, 3, 2, 1, 0, 12, 11, 10, 9, 8, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref char sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int groupCount = blockCount >> 2;
		int processedBlocks = 0;

		for (int i = 0; i < groupCount; ++i)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), table0, table1, table2, table3);
			Vector128<byte> second = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 16)), table0, table1, table2, table3);
			Vector128<byte> third = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 32)), table0, table1, table2, table3);
			Vector128<byte> fourth = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 48)), table0, table1, table2, table3);

			if (!IsValidAdvSimd(first & second & third & fourth))
			{
				break;
			}

			PackDecodedAdvSimd(first, extract).StoreUnsafe(ref destinationPointer);
			PackDecodedAdvSimd(second, extract).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 10));
			PackDecodedAdvSimd(third, extract).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 20));
			StoreDecoded(PackDecodedAdvSimd(fourth, extract), ref Unsafe.Add(ref destinationPointer, 30));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 4;
		}

		if (processedBlocks == groupCount * 4 && blockCount - processedBlocks >= 2)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), table0, table1, table2, table3);
			Vector128<byte> second = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 16)), table0, table1, table2, table3);

			if (IsValidAdvSimd(first & second))
			{
				PackDecodedAdvSimd(first, extract).StoreUnsafe(ref destinationPointer);
				StoreDecoded(PackDecodedAdvSimd(second, extract), ref Unsafe.Add(ref destinationPointer, 10));
				sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
				destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
				processedBlocks += 2;
			}
		}

		if (processedBlocks == blockCount - 1)
		{
			Vector128<byte> values = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), table0, table1, table2, table3);

			if (IsValidAdvSimd(values))
			{
				StoreDecoded(PackDecodedAdvSimd(values, extract), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}
}
