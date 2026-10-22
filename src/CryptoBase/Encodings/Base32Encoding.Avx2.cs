namespace CryptoBase.Encodings;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> MapSymbols(Vector256<byte> value, Vector256<sbyte> threshold, Vector256<byte> first, Vector256<byte> second)
	{
		Vector256<byte> mask = Vector256.GreaterThan(value.AsSByte(), threshold).AsByte();
		return value + Vector256.ConditionalSelect(mask, second, first);
	}

	// Each qword holds one 40-bit group as four big-endian 16-bit windows; the multiplies move the even and odd symbols into the low and high bytes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> SplitFour(ref byte source, Vector256<byte> indices)
	{
		Vector256<byte> input = Vector256.Create(Vector128.LoadUnsafe(ref source), Vector128.LoadUnsafe(ref source, 4));
		Vector256<ulong> windows = Avx2.Shuffle(input, indices).AsUInt64();
		Vector256<ushort> even = Avx2.MultiplyHigh((windows & Vector256.Create(0x03e00f803e00f800UL)).AsUInt16(), Vector256.Create(0x0800020000800020UL).AsUInt16());
		Vector256<ushort> odd = (windows & Vector256.Create(0x001f007c01f007c0UL)).AsUInt16() * Vector256.Create(0x0100004000100004UL).AsUInt16();
		return (even | odd).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> EncodeFour(ref byte source, Vector256<byte> indices, Vector256<sbyte> threshold, Vector256<byte> first, Vector256<byte> second)
	{
		return MapSymbols(SplitFour(ref source, indices), threshold, first, second);
	}

	// A 32-entry lookup from two in-lane shuffles. The first returns low[value & 15]. Subtracting 16 sets the high bit of values
	// 0-15, so the second shuffle returns zero for them, and maps 16-31 to 0-15, where (low ^ high)[value - 16] turns the first
	// result into high[value - 16].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> MapCustomSymbols(Vector256<byte> value, Vector256<byte> alphabetLow, Vector256<byte> alphabetLowXorHigh)
	{
		return Avx2.Shuffle(alphabetLow, value) ^ Avx2.Shuffle(alphabetLowXorHigh, value - Vector256.Create((byte)16));
	}

	// Groups 0-3 sit in qwords 0, 2, 1, 3 so the in-lane byte unpacks emit chars in source order.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreEncodedCharsUnpacked(Vector256<byte> value, ref char destination)
	{
		ref ushort destinationReference = ref Unsafe.As<char, ushort>(ref destination);
		Avx2.UnpackLow(value, Vector256<byte>.Zero).AsUInt16().StoreUnsafe(ref destinationReference);
		Avx2.UnpackHigh(value, Vector256<byte>.Zero).AsUInt16().StoreUnsafe(ref destinationReference, 16);
	}

	// For char, value must already hold the groups in the qword order StoreEncodedCharsUnpacked expects, which the char shuffle indices produce.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreSymbols<T>(Vector256<byte> value, ref T destination) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			value.StoreUnsafe(ref Unsafe.As<T, byte>(ref destination));
			return;
		}

		StoreEncodedCharsUnpacked(value, ref Unsafe.As<T, char>(ref destination));
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeAvx2<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector256<sbyte> threshold = Vector256.Create((sbyte)thresholdValue);
		Vector256<byte> first = Vector256.Create(firstValue);
		Vector256<byte> second = Vector256.Create(secondValue);
		Vector256<byte> indices = typeof(T) == typeof(char)
			? Vector256.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 11, 10, 12, 11, 13, 12, 14, 13, 2, 1, 3, 2, 4, 3, 5, 4, 12, 11, 13, 12, 14, 13, 15, 14)
			: Vector256.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8, 7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		int blockCount = GetEncodeBlockCount(source.Length, destination.Length, 4);
		int vectorCount = blockCount >> 2;

		if (vectorCount is 0)
		{
			return 0;
		}

		ref byte sourceReference = ref MemoryMarshal.GetReference(source);
		ref T destinationReference = ref MemoryMarshal.GetReference(destination);
		int remainderBlocks = blockCount & 3;
		nuint sourceOffset = 0;
		nuint destinationOffset = 0;

		while (true)
		{
			do
			{
				StoreSymbols(EncodeFour(ref Unsafe.Add(ref sourceReference, sourceOffset), indices, threshold, first, second), ref Unsafe.Add(ref destinationReference, destinationOffset));
				sourceOffset += 4 * InputBytesPerBlock;
				destinationOffset += 4 * OutputSymbolsPerBlock;
			} while (--vectorCount is not 0);

			if (remainderBlocks is 0)
			{
				return blockCount * InputBytesPerBlock;
			}

			sourceOffset -= (nuint)(4 - remainderBlocks) * InputBytesPerBlock;
			destinationOffset -= (nuint)(4 - remainderBlocks) * OutputSymbolsPerBlock;
			remainderBlocks = 0;
			vectorCount = 1;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetCustomEncodeTables(byte[] alphabet, out Vector256<byte> alphabetLow, out Vector256<byte> alphabetLowXorHigh)
	{
		ref byte alphabetReference = ref MemoryMarshal.GetArrayDataReference(alphabet);
		Vector128<byte> low = Vector128.LoadUnsafe(ref alphabetReference);
		Vector128<byte> lowXorHigh = low ^ Vector128.LoadUnsafe(ref alphabetReference, 16);
		alphabetLow = Vector256.Create(low, low);
		alphabetLowXorHigh = Vector256.Create(lowXorHigh, lowXorHigh);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private int EncodeAvx2Custom<T>(ReadOnlySpan<byte> source, Span<T> destination) where T : unmanaged
	{
		GetCustomEncodeTables(_alphabet, out Vector256<byte> alphabetLow, out Vector256<byte> alphabetLowXorHigh);
		Vector256<byte> indices = typeof(T) == typeof(char)
			? Vector256.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 11, 10, 12, 11, 13, 12, 14, 13, 2, 1, 3, 2, 4, 3, 5, 4, 12, 11, 13, 12, 14, 13, 15, 14)
			: Vector256.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8, 7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		int blockCount = GetEncodeBlockCount(source.Length, destination.Length, 4);
		int vectorCount = blockCount >> 2;

		if (vectorCount is 0)
		{
			return 0;
		}

		ref byte sourceReference = ref MemoryMarshal.GetReference(source);
		ref T destinationReference = ref MemoryMarshal.GetReference(destination);
		int remainderBlocks = blockCount & 3;
		nuint sourceOffset = 0;
		nuint destinationOffset = 0;

		while (true)
		{
			do
			{
				Vector256<byte> values = SplitFour(ref Unsafe.Add(ref sourceReference, sourceOffset), indices);
				StoreSymbols(MapCustomSymbols(values, alphabetLow, alphabetLowXorHigh), ref Unsafe.Add(ref destinationReference, destinationOffset));
				sourceOffset += 4 * InputBytesPerBlock;
				destinationOffset += 4 * OutputSymbolsPerBlock;
			} while (--vectorCount is not 0);

			if (remainderBlocks is 0)
			{
				return blockCount * InputBytesPerBlock;
			}

			sourceOffset -= (nuint)(4 - remainderBlocks) * InputBytesPerBlock;
			destinationOffset -= (nuint)(4 - remainderBlocks) * OutputSymbolsPerBlock;
			remainderBlocks = 0;
			vectorCount = 1;
		}
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
		return Avx2.Shuffle(merged, indices);
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

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int DecodeAvx2<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind) where T : unmanaged
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector256<byte> deltaCheck = Vector256.Create(deltaCheck128);
		Vector256<byte> deltaRebase = Vector256.Create(deltaRebase128);
		Vector256<byte> nibbleMask = Vector256.Create((byte)0x0f);
		Vector256<sbyte> lowerBound = Vector256.Create((sbyte)mapLowerBound);
		int blockCount = Math.Min(fullLength / 32, destination.Length / 20);
		ref T sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int pairCount = blockCount >> 1;
		const int stride = 128;
		int prefetchPairs = StreamPrefetch.Iterations(pairCount, stride);
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if (typeof(T) == typeof(char) && i < prefetchPairs)
			{
				StreamPrefetch.Bytes(ref sourcePointer, stride);
			}

			Vector256<byte> first = DecodeFour(LoadSymbols256(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> firstInvalidMask);
			Vector256<byte> second = DecodeFour(LoadSymbols256(ref Unsafe.Add(ref sourcePointer, 32)), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> secondInvalidMask);

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
			Vector256<byte> values = DecodeFour(LoadSymbols256(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector256<byte> invalidMask);

			if (IsValidAvx2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}
}
