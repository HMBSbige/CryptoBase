namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> MapSymbols(Vector256<byte> value, Vector256<sbyte> threshold, Vector256<byte> first, Vector256<byte> second)
	{
		Vector256<byte> mask = Vector256.GreaterThan(value.AsSByte(), threshold).AsByte();
		return value + Vector256.ConditionalSelect(mask, second, first);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> EncodeFour(Vector256<ulong> value, Vector256<sbyte> threshold, Vector256<byte> first, Vector256<byte> second)
	{
		Vector256<ulong> mask = Vector256.Create((ulong)SymbolMask);
		Vector256<ulong> result = value >>> 35 & mask;
		Vector256<ulong> next = (value >>> 30 & mask) << 8;
		Vector256<ulong> later = (value >>> 25 & mask) << 16;
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> PackFourFast(ref byte source)
	{
		return Vector256.Create(Pack5Fast(ref source), Pack5Fast(ref Unsafe.Add(ref source, 5)), Pack5Fast(ref Unsafe.Add(ref source, 10)), Pack5Fast(ref Unsafe.Add(ref source, 15)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> PackFour(ref byte source)
	{
		return Vector256.Create(Pack5(ref source), Pack5(ref Unsafe.Add(ref source, 5)), Pack5(ref Unsafe.Add(ref source, 10)), Pack5(ref Unsafe.Add(ref source, 15)));
	}

	private static int EncodeUtf8Avx2(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector256<sbyte> threshold = Vector256.Create((sbyte)thresholdValue);
		Vector256<byte> first = Vector256.Create(firstValue);
		Vector256<byte> second = Vector256.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 20 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 20, destinationRemaining / 32)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			EncodeFour(PackFourFast(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		int consumed = blockCount * 20;

		if (sourceRemaining - consumed >= 20 && destinationRemaining - blockCount * 32 >= 32)
		{
			EncodeFour(PackFour(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			consumed += 20;
		}

		return consumed;
	}

	private static int EncodeCharsAvx2(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector256<sbyte> threshold = Vector256.Create((sbyte)thresholdValue);
		Vector256<byte> first = Vector256.Create(firstValue);
		Vector256<byte> second = Vector256.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 20 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 20, destinationRemaining / 32)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			StoreEncodedChars(EncodeFour(PackFourFast(ref sourcePointer), threshold, first, second), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		int consumed = blockCount * 20;

		if (sourceRemaining - consumed >= 20 && destinationRemaining - blockCount * 32 >= 32)
		{
			StoreEncodedChars(EncodeFour(PackFour(ref sourcePointer), threshold, first, second), ref destinationPointer);
			consumed += 20;
		}

		return consumed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> DecodeFour(Vector256<byte> input, Vector256<byte> deltaCheck, Vector256<byte> deltaRebase, Vector256<byte> nibbleMask, Vector256<sbyte> lowerBound, out Vector256<byte> invalidMask)
	{
		Vector256<byte> hashKey = (input.AsUInt32() >>> 4).AsByte() & nibbleMask;
		Vector256<byte> check = input + Avx2.Shuffle(deltaCheck, hashKey);
		invalidMask = check | Vector256.GreaterThan(lowerBound, input.AsSByte()).AsByte();
		return input + Avx2.Shuffle(deltaRebase, hashKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsValidAvx2(Vector256<byte> invalidMask)
	{
		return invalidMask.ExtractMostSignificantBits() is 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> PackDecoded(Vector256<byte> values)
	{
		Vector256<short> pairs = Avx2.MultiplyAddAdjacent(values, Vector256.Create(0x01200120).AsSByte());
		Vector256<int> quads = Avx2.MultiplyAddAdjacent(pairs, Vector256.Create(0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400).AsInt16());
		Vector256<byte> merged = (quads.AsUInt64() | quads.AsUInt64() >>> 48).AsByte();
		Vector256<byte> indices = Vector256.Create((byte)2, 1, 0, 5, 4, 10, 9, 8, 13, 12, 0, 0, 0, 0, 0, 0, 18, 17, 16, 21, 20, 26, 25, 24, 29, 28, 16, 16, 16, 16, 16, 16);
		return Vector256.Shuffle(merged, indices);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreDecoded(Vector256<byte> packed, ref byte destination)
	{
		packed.GetLower().StoreUnsafe(ref destination);
		StoreDecoded(packed.GetUpper(), ref Unsafe.Add(ref destination, 10));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreDecodedOverlapping(Vector256<byte> packed, ref byte destination)
	{
		packed.GetLower().StoreUnsafe(ref destination);
		packed.GetUpper().StoreUnsafe(ref Unsafe.Add(ref destination, 10));
	}

	private static int DecodeUtf8Avx2(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector256<byte> deltaCheck = Vector256.Create(deltaCheck128);
		Vector256<byte> deltaRebase = Vector256.Create(deltaRebase128);
		Vector256<byte> nibbleMask = Vector256.Create((byte)0x0f);
		Vector256<sbyte> lowerBound = Vector256.Create((sbyte)mapLowerBound);
		int blockCount = Math.Min(fullLength / 32, destination.Length / 20);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> first = DecodeFour(Vector256.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> firstInvalidMask);
			Vector256<byte> second = DecodeFour(Vector256.LoadUnsafe(ref sourcePointer, 32), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> secondInvalidMask);

			if (!IsValidAvx2(firstInvalidMask | secondInvalidMask))
			{
				break;
			}

			StoreDecodedOverlapping(PackDecoded(first), ref destinationPointer);
			StoreDecoded(PackDecoded(second), ref Unsafe.Add(ref destinationPointer, 20));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 2;
		}

		if (processedBlocks == pairCount * 2 && (blockCount & 1) is not 0)
		{
			Vector256<byte> values = DecodeFour(Vector256.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> invalidMask);

			if (IsValidAvx2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}

	private static int DecodeCharsAvx2(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector256<byte> deltaCheck = Vector256.Create(deltaCheck128);
		Vector256<byte> deltaRebase = Vector256.Create(deltaRebase128);
		Vector256<byte> nibbleMask = Vector256.Create((byte)0x0f);
		Vector256<sbyte> lowerBound = Vector256.Create((sbyte)mapLowerBound);
		int blockCount = Math.Min(fullLength / 32, destination.Length / 20);
		ref char sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if
			(
				!TryNarrowAscii(ref sourcePointer, out Vector256<byte> firstInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 32), out Vector256<byte> secondInput)
			)
			{
				break;
			}

			Vector256<byte> first = DecodeFour(firstInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> firstInvalidMask);
			Vector256<byte> second = DecodeFour(secondInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> secondInvalidMask);

			if (!IsValidAvx2(firstInvalidMask | secondInvalidMask))
			{
				break;
			}

			StoreDecodedOverlapping(PackDecoded(first), ref destinationPointer);
			StoreDecoded(PackDecoded(second), ref Unsafe.Add(ref destinationPointer, 20));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 64);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 40);
			processedBlocks += 2;
		}

		if
		(
			processedBlocks == pairCount * 2
			&& (blockCount & 1) is not 0
			&& TryNarrowAscii(ref sourcePointer, out Vector256<byte> input)
		)
		{
			Vector256<byte> values = DecodeFour(input, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> invalidMask);

			if (IsValidAvx2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}
}
