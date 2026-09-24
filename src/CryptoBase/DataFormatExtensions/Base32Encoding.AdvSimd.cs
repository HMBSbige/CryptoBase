namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeTwoAdvSimd(Vector128<ulong> value, Vector128<ulong> mask0, Vector128<ulong> mask1, Vector128<ulong> mask2, Vector128<ulong> mask3, Vector128<ulong> mask4, Vector128<ulong> mask5, Vector128<ulong> mask6, Vector128<ulong> mask7, Vector128<sbyte> threshold, Vector128<byte> first, Vector128<byte> second)
	{
		Vector128<ulong> result = value >>> 35 & mask0;
		Vector128<ulong> next = value >>> 22 & mask1;
		Vector128<ulong> later = value >>> 9 & mask2;
		result |= next;
		next = value << 4 & mask3;
		later |= next;
		result |= later;
		next = value << 17 & mask4;
		later = value << 30 & mask5;
		next |= later;
		later = value << 43 & mask6;
		next |= later;
		result |= next;
		result |= value << 56 & mask7;
		return MapSymbols(result.AsByte(), threshold, first, second);
	}

	private static int EncodeUtf8AdvSimd(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		Vector128<ulong> mask0 = Vector128.Create((ulong)SymbolMask);
		Vector128<ulong> mask1 = mask0 << 8;
		Vector128<ulong> mask2 = mask0 << 16;
		Vector128<ulong> mask3 = mask0 << 24;
		Vector128<ulong> mask4 = mask0 << 32;
		Vector128<ulong> mask5 = mask0 << 40;
		Vector128<ulong> mask6 = mask0 << 48;
		Vector128<ulong> mask7 = mask0 << 56;
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstOffset, out byte secondOffset);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstOffset);
		Vector128<byte> second = Vector128.Create(secondOffset);

		int sourceRemaining = source.Length - sourceOffset;
		int blockCount = sourceRemaining >= 10 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 10, (destination.Length - destinationOffset) / 16)
			: 0;
		ref byte sourceReference = ref Unsafe.Add(ref source.GetReference(), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref destination.GetReference(), destinationOffset);
		int quadCount = blockCount >> 2;

		for (int i = 0; i < quadCount; ++i)
		{
			Vector128<ulong> value0 = PackTwoFast(ref sourceReference);
			Vector128<ulong> value1 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 10));
			Vector128<ulong> value2 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 20));
			Vector128<ulong> value3 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 30));
			EncodeTwoAdvSimd(value0, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref destinationReference);
			EncodeTwoAdvSimd(value1, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref Unsafe.Add(ref destinationReference, 16));
			EncodeTwoAdvSimd(value2, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref Unsafe.Add(ref destinationReference, 32));
			EncodeTwoAdvSimd(value3, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref Unsafe.Add(ref destinationReference, 48));
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}

		int pairCount = (blockCount & 3) >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<ulong> firstValue = PackTwoFast(ref sourceReference);
			Vector128<ulong> secondValue = PackTwoFast(ref Unsafe.Add(ref sourceReference, 10));
			EncodeTwoAdvSimd(firstValue, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref destinationReference);
			EncodeTwoAdvSimd(secondValue, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref Unsafe.Add(ref destinationReference, 16));
			sourceReference = ref Unsafe.Add(ref sourceReference, 20);
			destinationReference = ref Unsafe.Add(ref destinationReference, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			EncodeTwoAdvSimd(PackTwoFast(ref sourceReference), mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref destinationReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, 10);
			destinationReference = ref Unsafe.Add(ref destinationReference, 16);
		}

		int consumed = blockCount * 10;

		if (sourceRemaining - consumed >= 10 && destination.Length - destinationOffset - blockCount * 16 >= 16)
		{
			EncodeTwoAdvSimd(PackTwo(ref sourceReference), mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second).StoreUnsafe(ref destinationReference);
			consumed += 10;
		}

		return consumed;
	}

	private static int EncodeCharsAdvSimd(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		Vector128<ulong> mask0 = Vector128.Create((ulong)SymbolMask);
		Vector128<ulong> mask1 = mask0 << 8;
		Vector128<ulong> mask2 = mask0 << 16;
		Vector128<ulong> mask3 = mask0 << 24;
		Vector128<ulong> mask4 = mask0 << 32;
		Vector128<ulong> mask5 = mask0 << 40;
		Vector128<ulong> mask6 = mask0 << 48;
		Vector128<ulong> mask7 = mask0 << 56;
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstOffset, out byte secondOffset);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstOffset);
		Vector128<byte> second = Vector128.Create(secondOffset);

		int sourceRemaining = source.Length - sourceOffset;
		int blockCount = sourceRemaining >= 10 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 10, (destination.Length - destinationOffset) / 16)
			: 0;
		ref byte sourceReference = ref Unsafe.Add(ref source.GetReference(), sourceOffset);
		ref char destinationReference = ref Unsafe.Add(ref destination.GetReference(), destinationOffset);
		int quadCount = blockCount >> 2;

		for (int i = 0; i < quadCount; ++i)
		{
			Vector128<ulong> value0 = PackTwoFast(ref sourceReference);
			Vector128<ulong> value1 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 10));
			Vector128<ulong> value2 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 20));
			Vector128<ulong> value3 = PackTwoFast(ref Unsafe.Add(ref sourceReference, 30));
			StoreEncodedChars(EncodeTwoAdvSimd(value0, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref destinationReference);
			StoreEncodedChars(EncodeTwoAdvSimd(value1, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref Unsafe.Add(ref destinationReference, 16));
			StoreEncodedChars(EncodeTwoAdvSimd(value2, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref Unsafe.Add(ref destinationReference, 32));
			StoreEncodedChars(EncodeTwoAdvSimd(value3, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref Unsafe.Add(ref destinationReference, 48));
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}

		int pairCount = (blockCount & 3) >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<ulong> firstValue = PackTwoFast(ref sourceReference);
			Vector128<ulong> secondValue = PackTwoFast(ref Unsafe.Add(ref sourceReference, 10));
			StoreEncodedChars(EncodeTwoAdvSimd(firstValue, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref destinationReference);
			StoreEncodedChars(EncodeTwoAdvSimd(secondValue, mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref Unsafe.Add(ref destinationReference, 16));
			sourceReference = ref Unsafe.Add(ref sourceReference, 20);
			destinationReference = ref Unsafe.Add(ref destinationReference, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			StoreEncodedChars(EncodeTwoAdvSimd(PackTwoFast(ref sourceReference), mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref destinationReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, 10);
			destinationReference = ref Unsafe.Add(ref destinationReference, 16);
		}

		int consumed = blockCount * 10;

		if (sourceRemaining - consumed >= 10 && destination.Length - destinationOffset - blockCount * 16 >= 16)
		{
			StoreEncodedChars(EncodeTwoAdvSimd(PackTwo(ref sourceReference), mask0, mask1, mask2, mask3, mask4, mask5, mask6, mask7, threshold, first, second), ref destinationReference);
			consumed += 10;
		}

		return consumed;
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
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
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
		ref char sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int groupCount = blockCount >> 2;
		int processedBlocks = 0;

		for (int i = 0; i < groupCount; ++i)
		{
			if
			(
				!TryNarrowAscii(ref sourcePointer, out Vector128<byte> firstInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 16), out Vector128<byte> secondInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 32), out Vector128<byte> thirdInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 48), out Vector128<byte> fourthInput)
			)
			{
				break;
			}

			Vector128<byte> first = DecodeTwoAdvSimd(firstInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(secondInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);
			Vector128<byte> third = DecodeTwoAdvSimd(thirdInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> thirdValidMask);
			Vector128<byte> fourth = DecodeTwoAdvSimd(fourthInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> fourthValidMask);

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

		if
		(
			processedBlocks == groupCount * 4
			&& blockCount - processedBlocks >= 2
			&& TryNarrowAscii(ref sourcePointer, out Vector128<byte> remainingFirstInput)
			&& TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 16), out Vector128<byte> remainingSecondInput)
		)
		{
			Vector128<byte> first = DecodeTwoAdvSimd(remainingFirstInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> firstValidMask);
			Vector128<byte> second = DecodeTwoAdvSimd(remainingSecondInput, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> secondValidMask);

			if (IsValidAdvSimd(firstValidMask & secondValidMask))
			{
				PackDecodedAdvSimd(first, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC).StoreUnsafe(ref destinationPointer);
				StoreDecoded(PackDecodedAdvSimd(second, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref Unsafe.Add(ref destinationPointer, 10));
				sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
				destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
				processedBlocks += 2;
			}
		}

		if (processedBlocks == blockCount - 1 && TryNarrowAscii(ref sourcePointer, out Vector128<byte> input))
		{
			Vector128<byte> values = DecodeTwoAdvSimd(input, baseOffset, adjustedOffset, baseLimit, adjustedLimit, adjustment, out Vector128<byte> validMask);

			if (IsValidAdvSimd(validMask))
			{
				StoreDecoded(PackDecodedAdvSimd(values, indicesA, shiftsA, indicesB, shiftsB, indicesC, shiftsC), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}
}
