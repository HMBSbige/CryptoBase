namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeTwo(Vector128<byte> input, Vector128<byte> indices, Vector128<sbyte> threshold, Vector128<byte> first, Vector128<byte> second)
	{
		Vector128<ulong> windows = Ssse3.Shuffle(input, indices).AsUInt64();
		Vector128<ushort> even = Sse2.MultiplyHigh((windows & Vector128.Create(0x03e00f803e00f800UL)).AsUInt16(), Vector128.Create(0x0800020000800020UL).AsUInt16());
		Vector128<ushort> odd = (windows & Vector128.Create(0x001f007c01f007c0UL)).AsUInt16() * Vector128.Create(0x0100004000100004UL).AsUInt16();
		return MapSymbols((even | odd).AsByte(), threshold, first, second);
	}

	private static int EncodeSsse3<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstValue);
		Vector128<byte> second = Vector128.Create(secondValue);
		Vector128<byte> lowIndices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8);
		Vector128<byte> highIndices = Vector128.Create((byte)7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14);
		int blockCount = GetEncodeBlockCount(source.Length, destination.Length, 4);
		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref T destinationPointer = ref MemoryMarshal.GetReference(destination);
		int quadCount = blockCount >> 2;

		for (int i = 0; i < quadCount; ++i)
		{
			StoreSymbols(EncodeTwo(Vector128.LoadUnsafe(ref sourcePointer), lowIndices, threshold, first, second), ref destinationPointer);
			StoreSymbols(EncodeTwo(Vector128.LoadUnsafe(ref sourcePointer, 4), highIndices, threshold, first, second), ref Unsafe.Add(ref destinationPointer, 16));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		int remainder = blockCount & 3;

		if (remainder is not 0)
		{
			// Re-encode the last four whole blocks; one or two leftover blocks only need the last pair.
			int lastQuad = blockCount - 4;
			ref byte lastSource = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), lastQuad * InputBytesPerBlock);
			ref T lastDestination = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), lastQuad * OutputSymbolsPerBlock);

			if (remainder is 3)
			{
				StoreSymbols(EncodeTwo(Vector128.LoadUnsafe(ref lastSource), lowIndices, threshold, first, second), ref lastDestination);
			}

			StoreSymbols(EncodeTwo(Vector128.LoadUnsafe(ref lastSource, 4), highIndices, threshold, first, second), ref Unsafe.Add(ref lastDestination, 16));
		}

		return blockCount * InputBytesPerBlock;
	}

	private static int EncodeSsse3Short<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector128<sbyte> threshold = Vector128.Create((sbyte)thresholdValue);
		Vector128<byte> first = Vector128.Create(firstValue);
		Vector128<byte> second = Vector128.Create(secondValue);
		Vector128<byte> indices = Vector128.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 14, 7, 15, 14);
		int blockCount = GetEncodeShortBlockCount(source.Length, destination.Length);
		ref byte sourceReference = ref MemoryMarshal.GetReference(source);
		ref T destinationReference = ref MemoryMarshal.GetReference(destination);
		StoreSymbols(EncodeTwo(LoadTenBytes(ref sourceReference), indices, threshold, first, second), ref destinationReference);

		if (blockCount is 3)
		{
			StoreSymbols(EncodeTwo(LoadTenBytes(ref Unsafe.Add(ref sourceReference, InputBytesPerBlock)), indices, threshold, first, second), ref Unsafe.Add(ref destinationReference, OutputSymbolsPerBlock));
		}

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecodeTwoSse2(Vector128<byte> input, Vector128<byte> deltaCheck, Vector128<byte> deltaRebase, Vector128<byte> nibbleMask, Vector128<sbyte> lowerBound, out Vector128<byte> invalidMask)
	{
		Vector128<byte> hashKey = (input.AsUInt32() >>> 4).AsByte() & nibbleMask;
		Vector128<byte> check = input + Ssse3.Shuffle(deltaCheck, hashKey);
		invalidMask = check | Vector128.GreaterThan(lowerBound, input.AsSByte()).AsByte();
		return input + Ssse3.Shuffle(deltaRebase, hashKey);
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
		return Ssse3.Shuffle(merged, Vector128.Create((byte)2, 1, 0, 5, 4, 10, 9, 8, 13, 12, 0, 0, 0, 0, 0, 0));
	}

	private static int DecodeVector128<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind) where T : unmanaged
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck, out Vector128<byte> deltaRebase, out byte mapLowerBound);
		Vector128<byte> nibbleMask = Vector128.Create((byte)0x0f);
		Vector128<sbyte> lowerBound = Vector128.Create((sbyte)mapLowerBound);

		int blockCount = Math.Min(fullLength / 16, destination.Length / 10);
		ref T sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<byte> first = DecodeTwoSse2(LoadSymbols128(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> firstInvalidMask);
			Vector128<byte> second = DecodeTwoSse2(LoadSymbols128(ref Unsafe.Add(ref sourcePointer, 16)), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> secondInvalidMask);

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
			Vector128<byte> values = DecodeTwoSse2(LoadSymbols128(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector128<byte> invalidMask);

			if (IsValidSse2(invalidMask))
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 16;
	}
}
