namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetEncodeAlphabet(byte alphabetKind, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh)
	{
		ReadOnlySpan<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? "0123456789ABCDEFGHIJKLMNOPQRSTUV"u8 : "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8;
		alphabetLow = Vector128.Create(alphabet);
		alphabetHigh = Vector128.Create(alphabet.Slice(16));
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
	private static int EncodeUtf8AdvSimd(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		GetEncodeAlphabet(alphabetKind, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> lowIndices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8);
		Vector128<byte> highIndices = Vector128.Create((byte)7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeTwoBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		int quadCount = blockCount >> 2;

		for (int i = 0; i < quadCount; ++i)
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

		if ((blockCount & 2) is not 0)
		{
			EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference);
			EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationReference, 16);
			sourceReference = ref Unsafe.Add(ref sourceReference, 20);
			destinationReference = ref Unsafe.Add(ref destinationReference, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector128<byte> encoded = blockCount is 1
				? EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh)
				: EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Subtract(ref sourceReference, 6)), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh);
			encoded.StoreUnsafe(ref destinationReference);
		}

		return blockCount * 10;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeCharsAdvSimd(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		GetEncodeAlphabet(alphabetKind, out Vector128<byte> alphabetLow, out Vector128<byte> alphabetHigh);
		Vector128<byte> lowIndices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8);
		Vector128<byte> highIndices = Vector128.Create((byte)7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		Vector128<short> evenShifts = Vector128.Create(-11, -9, -7, -5, -11, -9, -7, -5);
		Vector128<short> oddShifts = Vector128.Create(2, 4, 6, 8, 2, 4, 6, 8);
		int blockCount = GetEncodeTwoBlockCount(source.Length - sourceOffset, destination.Length - destinationOffset);
		ref byte sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref char destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		int quadCount = blockCount >> 2;

		for (int i = 0; i < quadCount; ++i)
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

		if ((blockCount & 2) is not 0)
		{
			StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref destinationReference);
			StoreEncodedChars(EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference, 4), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationReference, 16));
			sourceReference = ref Unsafe.Add(ref sourceReference, 20);
			destinationReference = ref Unsafe.Add(ref destinationReference, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector128<byte> encoded = blockCount is 1
				? EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourceReference), lowIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh)
				: EncodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Subtract(ref sourceReference, 6)), highIndices, evenShifts, oddShifts, alphabetLow, alphabetHigh);
			StoreEncodedChars(encoded, ref destinationReference);
		}

		return blockCount * 10;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetDecodeMap(byte alphabetKind, out byte baseOffset, out byte adjustedOffset, out byte baseLimit, out byte adjustedLimit, out byte adjustment)
	{
		if (alphabetKind is Rfc4648HexAlphabetKind)
		{
			baseOffset = 256 - '0';
			adjustedOffset = 256 - 'A';
			baseLimit = 9;
			adjustedLimit = 21;
			adjustment = 256 - 7;
		}
		else
		{
			baseOffset = 256 - 'A';
			adjustedOffset = 256 - '2';
			baseLimit = 25;
			adjustedLimit = 5;
			adjustment = 'A' - '2' + 26;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecodeTwoAdvSimd(Vector128<byte> input, Vector128<byte> baseOffset, Vector128<byte> adjustedOffset, Vector128<byte> baseLimit, Vector128<byte> adjustedLimit, Vector128<byte> adjustment, out Vector128<byte> validMask)
	{
		Vector128<byte> baseValues = input + baseOffset;
		Vector128<byte> adjustedValues = input + adjustedOffset;
		Vector128<byte> baseMask = Vector128.LessThanOrEqual(baseValues, baseLimit);
		Vector128<byte> adjustedMask = Vector128.LessThanOrEqual(adjustedValues, adjustedLimit);
		validMask = baseMask | adjustedMask;
		return baseValues + (adjustedMask & adjustment);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsValidAdvSimd(Vector128<byte> validMask)
	{
		return AdvSimd.Arm64.MinAcross(validMask).GetElement(0) is byte.MaxValue;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PackDecodedAdvSimd(Vector128<byte> values, Vector128<byte> indicesA, Vector128<sbyte> shiftsA, Vector128<byte> indicesB, Vector128<sbyte> shiftsB, Vector128<byte> indicesC, Vector128<sbyte> shiftsC)
	{
		Vector128<byte> a = AdvSimd.ShiftLogical(Vector128.Shuffle(values, indicesA), shiftsA);
		Vector128<byte> b = AdvSimd.ShiftLogical(Vector128.Shuffle(values, indicesB), shiftsB);
		Vector128<byte> c = AdvSimd.ShiftLogical(Vector128.Shuffle(values, indicesC), shiftsC);
		return a | b | c;
	}

	private static int DecodeUtf8AdvSimd(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeMap(alphabetKind, out byte mapBaseOffset, out byte mapAdjustedOffset, out byte mapBaseLimit, out byte mapAdjustedLimit, out byte mapAdjustment);
		Vector128<byte> baseOffset = Vector128.Create(mapBaseOffset);
		Vector128<byte> adjustedOffset = Vector128.Create(mapAdjustedOffset);
		Vector128<byte> baseLimit = Vector128.Create(mapBaseLimit);
		Vector128<byte> adjustedLimit = Vector128.Create(mapAdjustedLimit);
		Vector128<byte> adjustment = Vector128.Create(mapAdjustment);
		Vector128<byte> indicesA = Vector128.Create(0, 1, 3, 4, 6, 8, 9, 11, 12, 14, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsA = Vector128.Create(3, 6, 4, 7, 5, 3, 6, 4, 7, 5, 0, 0, 0, 0, 0, 0);
		Vector128<byte> indicesB = Vector128.Create(1, 2, 4, 5, 7, 9, 10, 12, 13, 15, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsB = Vector128.Create(-2, 1, -1, 2, 0, -2, 1, -1, 2, 0, 0, 0, 0, 0, 0, 0);
		Vector128<byte> indicesC = Vector128.Create(byte.MaxValue, 3, byte.MaxValue, 6, byte.MaxValue, byte.MaxValue, 11, byte.MaxValue, 14, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsC = Vector128.Create(0, -4, 0, -3, 0, 0, -4, 0, -3, 0, 0, 0, 0, 0, 0, 0);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int groupCount = blockCount >> 2;
		int processedBlocks = 0;

		for (int i = 0; i < groupCount; ++i)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 16)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);
			Vector128<byte> third = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 32)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> thirdValidMask);
			Vector128<byte> fourth = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 48)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> fourthValidMask);

			if (!IsValidAdvSimd(firstValidMask & secondValidMask & thirdValidMask & fourthValidMask))
			{
				break;
			}

			PackDecodedAdvSimd(first, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref destinationPointer);
			PackDecodedAdvSimd(second, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 10));
			PackDecodedAdvSimd(third, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 20));
			StoreDecoded(PackDecodedAdvSimd(fourth, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref Unsafe.Add(ref destinationPointer, 30));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 4;
		}

		if (processedBlocks == groupCount * 4 && blockCount - processedBlocks >= 2)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref Unsafe.Add(ref sourcePointer, 16)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);

			if (IsValidAdvSimd(firstValidMask & secondValidMask))
			{
				PackDecodedAdvSimd(first, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref destinationPointer);
				StoreDecoded(PackDecodedAdvSimd(second, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref Unsafe.Add(ref destinationPointer, 10));
				sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
				destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
				processedBlocks += 2;
			}
		}

		if (processedBlocks == blockCount - 1)
		{
			Vector128<byte> values = DecodeTwoAdvSimd(Vector128.LoadUnsafe(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> validMask);

			if (IsValidAdvSimd(validMask))
			{
				StoreDecoded(PackDecodedAdvSimd(values, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}

	private static int DecodeCharsAdvSimd(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeMap(alphabetKind, out byte mapBaseOffset, out byte mapAdjustedOffset, out byte mapBaseLimit, out byte mapAdjustedLimit, out byte mapAdjustment);
		Vector128<byte> baseOffset = Vector128.Create(mapBaseOffset);
		Vector128<byte> adjustedOffset = Vector128.Create(mapAdjustedOffset);
		Vector128<byte> baseLimit = Vector128.Create(mapBaseLimit);
		Vector128<byte> adjustedLimit = Vector128.Create(mapAdjustedLimit);
		Vector128<byte> adjustment = Vector128.Create(mapAdjustment);
		Vector128<byte> indicesA = Vector128.Create(0, 1, 3, 4, 6, 8, 9, 11, 12, 14, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsA = Vector128.Create(3, 6, 4, 7, 5, 3, 6, 4, 7, 5, 0, 0, 0, 0, 0, 0);
		Vector128<byte> indicesB = Vector128.Create(1, 2, 4, 5, 7, 9, 10, 12, 13, 15, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsB = Vector128.Create(-2, 1, -1, 2, 0, -2, 1, -1, 2, 0, 0, 0, 0, 0, 0, 0);
		Vector128<byte> indicesC = Vector128.Create(byte.MaxValue, 3, byte.MaxValue, 6, byte.MaxValue, byte.MaxValue, 11, byte.MaxValue, 14, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue);
		Vector128<sbyte> shiftsC = Vector128.Create(0, -4, 0, -3, 0, 0, -4, 0, -3, 0, 0, 0, 0, 0, 0, 0);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref char sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int groupCount = blockCount >> 2;
		int processedBlocks = 0;

		for (int i = 0; i < groupCount; ++i)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 16)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);
			Vector128<byte> third = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 32)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> thirdValidMask);
			Vector128<byte> fourth = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 48)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> fourthValidMask);

			if (!IsValidAdvSimd(firstValidMask & secondValidMask & thirdValidMask & fourthValidMask))
			{
				break;
			}

			PackDecodedAdvSimd(first, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref destinationPointer);
			PackDecodedAdvSimd(second, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 10));
			PackDecodedAdvSimd(third, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 20));
			StoreDecoded(PackDecodedAdvSimd(fourth, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref Unsafe.Add(ref destinationPointer, 30));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 4;
		}

		if (processedBlocks == groupCount * 4 && blockCount - processedBlocks >= 2)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref Unsafe.Add(ref sourcePointer, 16)), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);

			if (IsValidAdvSimd(firstValidMask & secondValidMask))
			{
				PackDecodedAdvSimd(first, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref destinationPointer);
				StoreDecoded(PackDecodedAdvSimd(second, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref Unsafe.Add(ref destinationPointer, 10));
				sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
				destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
				processedBlocks += 2;
			}
		}

		if (processedBlocks == blockCount - 1)
		{
			Vector128<byte> values = DecodeTwoAdvSimd(LoadNarrowSaturated128(ref sourcePointer), baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> validMask);

			if (IsValidAdvSimd(validMask))
			{
				StoreDecoded(PackDecodedAdvSimd(values, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}
}
