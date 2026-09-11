namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeTwo(Vector128<ulong> value, Vector128<sbyte> threshold, Vector128<byte> first, Vector128<byte> second)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)SymbolMask);
		Vector128<ulong> result = value >>> 35 & mask;
		Vector128<ulong> next = (value >>> 30 & mask) << 8;
		Vector128<ulong> later = (value >>> 25 & mask) << 16;
		result |= next;
		next = (value >>> 20 & mask) << 24;
		later |= next;
		result |= later;
		next = (value >>> 15 & mask) << 32;
		later = (value >>> 10 & mask) << 40;
		next |= later;
		later = (value >>> 5 & mask) << 48;
		next |= later;
		result |= next;
		result |= (value & mask) << 56;
		return MapSymbols(result.AsByte(), threshold, first, second);
	}

	private static int EncodeUtf8Ssse3(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstValue);
		Vector128<byte> second = Vector128.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 10 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 10, destinationRemaining / 16)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			EncodeTwo(PackTwoFast(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 10);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 16);
		}

		int consumed = blockCount * 10;

		if (sourceRemaining - consumed >= 10 && destinationRemaining - blockCount * 16 >= 16)
		{
			EncodeTwo(PackTwo(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			consumed += 10;
		}

		return consumed;
	}

	private static int EncodeCharsSsse3(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstValue);
		Vector128<byte> second = Vector128.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 10 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 10, destinationRemaining / 16)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			StoreEncodedChars(EncodeTwo(PackTwoFast(ref sourcePointer), threshold, first, second), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 10);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 16);
		}

		int consumed = blockCount * 10;

		if (sourceRemaining - consumed >= 10 && destinationRemaining - blockCount * 16 >= 16)
		{
			StoreEncodedChars(EncodeTwo(PackTwo(ref sourcePointer), threshold, first, second), ref destinationPointer);
			consumed += 10;
		}

		return consumed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecodeTwoSse2(Vector128<byte> input, Vector128<byte> deltaCheck, Vector128<byte> deltaRebase, Vector128<byte> nibbleMask, Vector128<sbyte> lowerBound, out Vector128<byte> invalidMask)
	{
		Vector128<byte> hashKey = (input.AsUInt32() >>> 4).AsByte() & nibbleMask;
		Vector128<byte> check = input + Vector128.ShuffleNative(deltaCheck, hashKey);
		invalidMask = check | Vector128.GreaterThan(lowerBound, input.AsSByte()).AsByte();
		return input + Vector128.ShuffleNative(deltaRebase, hashKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsValidSse2(Vector128<byte> invalidMask)
	{
		return invalidMask.ExtractMostSignificantBits() is 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PackDecoded(Vector128<byte> values)
	{
		Vector128<short> pairs = Ssse3.MultiplyAddAdjacent(values, Vector128.Create(0x01200120).AsSByte());
		Vector128<int> quads = Sse2.MultiplyAddAdjacent(pairs, Vector128.Create(0x00104000, 0x00010400, 0x00104000, 0x00010400).AsInt16());
		Vector128<byte> merged = (quads.AsUInt64() | quads.AsUInt64() >>> 48).AsByte();
		return Vector128.Shuffle(merged, Vector128.Create((byte)2, 1, 0, 5, 4, 10, 9, 8, 13, 12, 0, 0, 0, 0, 0, 0));
	}

	private static int DecodeUtf8Vector128(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck, out Vector128<byte> deltaRebase, out byte mapLowerBound);
		Vector128<byte> nibbleMask = Vector128.Create((byte)0x0f);
		Vector128<sbyte> lowerBound = Vector128.Create((sbyte)mapLowerBound);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<byte> first = DecodeTwoSse2(Vector128.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> firstInvalidMask);
			Vector128<byte> second = DecodeTwoSse2(Vector128.LoadUnsafe(ref sourcePointer, 16), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> secondInvalidMask);

			if (!IsValidSse2(firstInvalidMask | secondInvalidMask))
			{
				break;
			}

			PackDecoded(first).StoreUnsafe(ref destinationPointer);
			StoreDecoded(PackDecoded(second), ref Unsafe.Add(ref destinationPointer, 10));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
			processedBlocks += 2;
		}

		if (processedBlocks == pairCount * 2 && (blockCount & 1) is not 0)
		{
			Vector128<byte> values = DecodeTwoSse2(Vector128.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> invalidMask);

			if (IsValidSse2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}

	private static int DecodeCharsVector128(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck, out Vector128<byte> deltaRebase, out byte mapLowerBound);
		Vector128<byte> nibbleMask = Vector128.Create((byte)0x0f);
		Vector128<sbyte> lowerBound = Vector128.Create((sbyte)mapLowerBound);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref char sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if
			(
				!TryNarrowAscii(ref sourcePointer, out Vector128<byte> firstInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 16), out Vector128<byte> secondInput)
			)
			{
				break;
			}

			Vector128<byte> first = DecodeTwoSse2(firstInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> firstInvalidMask);
			Vector128<byte> second = DecodeTwoSse2(secondInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> secondInvalidMask);

			if (!IsValidSse2(firstInvalidMask | secondInvalidMask))
			{
				break;
			}

			PackDecoded(first).StoreUnsafe(ref destinationPointer);
			StoreDecoded(PackDecoded(second), ref Unsafe.Add(ref destinationPointer, 10));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 32);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 20);
			processedBlocks += 2;
		}

		if
		(
			processedBlocks == pairCount * 2
			&& (blockCount & 1) is not 0
			&& TryNarrowAscii(ref sourcePointer, out Vector128<byte> input)
		)
		{
			Vector128<byte> values = DecodeTwoSse2(input, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> invalidMask);

			if (IsValidSse2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}
}
