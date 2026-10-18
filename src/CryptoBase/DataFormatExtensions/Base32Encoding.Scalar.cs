namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	private const int Pack5FastOverReadBytes = sizeof(ulong) - InputBytesPerBlock;
	private const ulong ByteLaneOnes = 0x0101_0101_0101_0101;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Pack5(ref byte source)
	{
		return (ulong)source << 32
				| (ulong)Unsafe.Add(ref source, 1) << 24
				| (ulong)Unsafe.Add(ref source, 2) << 16
				| (ulong)Unsafe.Add(ref source, 3) << 8
				| Unsafe.Add(ref source, 4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Pack5Fast(ref byte source)
	{
		return BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref source)) >> 24;
	}

	// T is char or byte, and the type test folds at JIT time. Generic CreateChecked goes through the INumberBase conversion methods and is
	// only free when they all inline; once a large caller runs out of inline budget, every symbol pays for those calls.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static T ToSymbol<T>(byte value) where T : unmanaged
	{
		return typeof(T) == typeof(char) ? Unsafe.BitCast<char, T>((char)value) : Unsafe.BitCast<byte, T>(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int FromSymbol<T>(T symbol) where T : unmanaged
	{
		return typeof(T) == typeof(char) ? Unsafe.BitCast<T, char>(symbol) : Unsafe.BitCast<T, byte>(symbol);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodeBlock(ref byte source, ref char destination, ref byte alphabet)
	{
		ulong value = Pack5(ref source);
		Unsafe.Add(ref destination, 0) = (char)Unsafe.Add(ref alphabet, (int)(value >> 35));
		Unsafe.Add(ref destination, 1) = (char)Unsafe.Add(ref alphabet, (int)(value >> 30 & SymbolMask));
		Unsafe.Add(ref destination, 2) = (char)Unsafe.Add(ref alphabet, (int)(value >> 25 & SymbolMask));
		Unsafe.Add(ref destination, 3) = (char)Unsafe.Add(ref alphabet, (int)(value >> 20 & SymbolMask));
		Unsafe.Add(ref destination, 4) = (char)Unsafe.Add(ref alphabet, (int)(value >> 15 & SymbolMask));
		Unsafe.Add(ref destination, 5) = (char)Unsafe.Add(ref alphabet, (int)(value >> 10 & SymbolMask));
		Unsafe.Add(ref destination, 6) = (char)Unsafe.Add(ref alphabet, (int)(value >> 5 & SymbolMask));
		Unsafe.Add(ref destination, 7) = (char)Unsafe.Add(ref alphabet, (int)(value & SymbolMask));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodePackedBlock(ulong value, ref byte destination, ref byte alphabet)
	{
		Debug.Assert(value >> 40 is 0);
		Unsafe.Add(ref destination, 0) = Unsafe.Add(ref alphabet, (int)(value >> 35));
		Unsafe.Add(ref destination, 1) = Unsafe.Add(ref alphabet, (int)(value >> 30 & SymbolMask));
		Unsafe.Add(ref destination, 2) = Unsafe.Add(ref alphabet, (int)(value >> 25 & SymbolMask));
		Unsafe.Add(ref destination, 3) = Unsafe.Add(ref alphabet, (int)(value >> 20 & SymbolMask));
		Unsafe.Add(ref destination, 4) = Unsafe.Add(ref alphabet, (int)(value >> 15 & SymbolMask));
		Unsafe.Add(ref destination, 5) = Unsafe.Add(ref alphabet, (int)(value >> 10 & SymbolMask));
		Unsafe.Add(ref destination, 6) = Unsafe.Add(ref alphabet, (int)(value >> 5 & SymbolMask));
		Unsafe.Add(ref destination, 7) = Unsafe.Add(ref alphabet, (int)(value & SymbolMask));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncodeBlock(ref byte source, ref byte destination, ref byte alphabet)
	{
		EncodePackedBlock(Pack5(ref source), ref destination, ref alphabet);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void EncodeUtf8ScalarBatches(ref byte sourceReference, ref byte destinationReference, ref byte alphabetReference, int octCount)
	{
		for (int i = 0; i < octCount; ++i)
		{
			ulong value0 = Pack5Fast(ref sourceReference);
			ulong value1 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 5));
			ulong value2 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 10));
			ulong value3 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 15));
			ulong value4 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 20));
			ulong value5 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 25));
			ulong value6 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 30));
			ulong value7 = Pack5Fast(ref Unsafe.Add(ref sourceReference, 35));
			EncodePackedBlock(value0, ref destinationReference, ref alphabetReference);
			EncodePackedBlock(value1, ref Unsafe.Add(ref destinationReference, 8), ref alphabetReference);
			EncodePackedBlock(value2, ref Unsafe.Add(ref destinationReference, 16), ref alphabetReference);
			EncodePackedBlock(value3, ref Unsafe.Add(ref destinationReference, 24), ref alphabetReference);
			EncodePackedBlock(value4, ref Unsafe.Add(ref destinationReference, 32), ref alphabetReference);
			EncodePackedBlock(value5, ref Unsafe.Add(ref destinationReference, 40), ref alphabetReference);
			EncodePackedBlock(value6, ref Unsafe.Add(ref destinationReference, 48), ref alphabetReference);
			EncodePackedBlock(value7, ref Unsafe.Add(ref destinationReference, 56), ref alphabetReference);
			sourceReference = ref Unsafe.Add(ref sourceReference, 40);
			destinationReference = ref Unsafe.Add(ref destinationReference, 64);
		}
	}

	// The final one to four bytes, big-endian in the top of a uint and zero filled. Inputs of four bytes or more read the last four bytes and
	// shift the already encoded ones out, so the common case is one load without a branch per byte.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ReadTail(ReadOnlySpan<byte> source, int remaining)
	{
		if (source.Length >= sizeof(uint))
		{
			uint last = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref MemoryMarshal.GetReference(source), source.Length - sizeof(uint)));
			return BinaryPrimitives.ReverseEndianness(last) << (sizeof(uint) - remaining) * 8;
		}

		uint value = (uint)source[0] << 24;

		if (remaining > 1)
		{
			value |= (uint)source[1] << 16;
		}

		if (remaining > 2)
		{
			value |= (uint)source[2] << 8;
		}

		return value;
	}

	// Spreads the eight 5-bit values of a block into the bytes of a ulong, first symbol in the lowest byte: each step moves the upper half of
	// every field up, so 40 bits become two 20-bit, four 10-bit and finally eight 5-bit fields.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong SplitBlockValues(ulong block)
	{
		block = block & 0xF_FFFF | (block & 0xFF_FFF0_0000) << 12;
		block = block & 0x03FF_0000_03FF | (block & 0x000F_FC00_000F_FC00) << 6;
		block = block & 0x001F_001F_001F_001F | (block & 0x03E0_03E0_03E0_03E0) << 3;
		return BinaryPrimitives.ReverseEndianness(block);
	}

	// SWAR form of the SIMD encode map: bytes above the threshold get the second offset. Values stay below 32 and symbols below 128,
	// so no addition carries into the next byte.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong MapBlockSymbols(ulong values, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte threshold, out byte first, out byte second);
		ulong above = (values + ByteLaneOnes * (byte)(0x7F - threshold) >> 7 & ByteLaneOnes) * byte.MaxValue;
		return values + (ByteLaneOnes * first ^ above & ByteLaneOnes * (byte)(first ^ second));
	}

	// The eight values index the 32-byte custom table at once: two 16-entry shuffles on x86, where bit 4 of each value picks the half, and
	// one two-register table lookup on ARM64. Elsewhere eight independent loads; a loop over the symbol count would chain them through the
	// accumulator.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong LookupBlockSymbols(ulong values, ref byte alphabet)
	{
		if (Ssse3.IsSupported || AdvSimd.Arm64.IsSupported)
		{
			Vector128<byte> indices = Vector128.CreateScalarUnsafe(values).AsByte();
			Vector128<byte> low = Vector128.LoadUnsafe(ref alphabet);
			Vector128<byte> high = Vector128.LoadUnsafe(ref alphabet, 16);
			Vector128<byte> symbols = AdvSimd.Arm64.IsSupported
				? AdvSimd.Arm64.VectorTableLookup((low, high), indices)
				: Vector128.ConditionalSelect(Vector128.GreaterThan(indices.AsSByte(), Vector128.Create((sbyte)15)).AsByte(), Ssse3.Shuffle(high, indices), Ssse3.Shuffle(low, indices));
			return symbols.AsUInt64().ToScalar();
		}

		return Unsafe.Add(ref alphabet, (nuint)(values & SymbolMask))
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 8 & SymbolMask)) << 8
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 16 & SymbolMask)) << 16
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 24 & SymbolMask)) << 24
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 32 & SymbolMask)) << 32
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 40 & SymbolMask)) << 40
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 48 & SymbolMask)) << 48
			| (ulong)Unsafe.Add(ref alphabet, (nuint)(values >> 56)) << 56;
	}

	// Builds the tail block as eight symbol bytes in one ulong: no per-symbol bounds checks and, for the built-in alphabets, no table loads.
	// A padded block is always eight symbols and goes out in a single store.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EncodeTail<T>(ReadOnlySpan<byte> source, int remaining, int symbolCount, Span<T> destination) where T : unmanaged
	{
		ulong values = SplitBlockValues((ulong)ReadTail(source, remaining) << 8);
		ulong symbols = _alphabetKind is CustomAlphabetKind
			? LookupBlockSymbols(values, ref MemoryMarshal.GetArrayDataReference(_alphabet))
			: MapBlockSymbols(values, _alphabetKind);

		if (destination.Length is OutputSymbolsPerBlock)
		{
			ulong keep = (1UL << symbolCount * 8) - 1;
			symbols = symbols & keep | ByteLaneOnes * _padding & ~keep;

			ref T destinationReference = ref MemoryMarshal.GetReference(destination);

			if (typeof(T) == typeof(char))
			{
				Vector128.WidenLower(Vector128.CreateScalarUnsafe(symbols).AsByte()).StoreUnsafe(ref Unsafe.As<T, ushort>(ref destinationReference));
			}
			else
			{
				Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref destinationReference), symbols);
			}

			return;
		}

		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = ToSymbol<T>((byte)(symbols >> i * 8));
		}
	}

	private int DecodeScalar<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength) where T : unmanaged
	{
		int blockCount = Math.Min(fullLength / OutputSymbolsPerBlock, destination.Length / InputBytesPerBlock);
		ref T sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		ref byte decodeTable = ref MemoryMarshal.GetArrayDataReference(_decodeTable);
		int processedBlocks = 0;

		for (; processedBlocks < blockCount; ++processedBlocks)
		{
			if (!TryDecodeBlock(ref sourcePointer, ref destinationPointer, ref decodeTable))
			{
				break;
			}

			sourcePointer = ref Unsafe.Add(ref sourcePointer, OutputSymbolsPerBlock);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, InputBytesPerBlock);
		}

		return processedBlocks * OutputSymbolsPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock(ref char source, ref byte destination, ref byte decodeTable)
	{
		uint s0 = source;
		uint s1 = Unsafe.Add(ref source, 1);
		uint s2 = Unsafe.Add(ref source, 2);
		uint s3 = Unsafe.Add(ref source, 3);
		uint s4 = Unsafe.Add(ref source, 4);
		uint s5 = Unsafe.Add(ref source, 5);
		uint s6 = Unsafe.Add(ref source, 6);
		uint s7 = Unsafe.Add(ref source, 7);

		if ((s0 | s1 | s2 | s3 | s4 | s5 | s6 | s7) > 0x7FU)
		{
			return false;
		}

		int v0 = Unsafe.Add(ref decodeTable, (int)s0);
		int v1 = Unsafe.Add(ref decodeTable, (int)s1);
		int v2 = Unsafe.Add(ref decodeTable, (int)s2);
		int v3 = Unsafe.Add(ref decodeTable, (int)s3);
		int v4 = Unsafe.Add(ref decodeTable, (int)s4);
		int v5 = Unsafe.Add(ref decodeTable, (int)s5);
		int v6 = Unsafe.Add(ref decodeTable, (int)s6);
		int v7 = Unsafe.Add(ref decodeTable, (int)s7);

		if ((v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) is InvalidSymbol)
		{
			return false;
		}

		WriteDecodedBlock(ref destination, v0, v1, v2, v3, v4, v5, v6, v7);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock(ref byte source, ref byte destination, ref byte decodeTable)
	{
		int v0 = Unsafe.Add(ref decodeTable, source);
		int v1 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 1));
		int v2 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 2));
		int v3 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 3));
		int v4 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 4));
		int v5 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 5));
		int v6 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 6));
		int v7 = Unsafe.Add(ref decodeTable, Unsafe.Add(ref source, 7));

		if ((v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) > SymbolMask)
		{
			return false;
		}

		WriteDecodedBlock(ref destination, v0, v1, v2, v3, v4, v5, v6, v7);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryDecodeBlock<T>(ReadOnlySpan<T> source, int sourceOffset, Span<byte> destination, int destinationOffset) where T : unmanaged
	{
		ref T sourceReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), sourceOffset);
		ref byte destinationReference = ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), destinationOffset);
		ref byte decodeTableReference = ref MemoryMarshal.GetArrayDataReference(_decodeTable);
		return TryDecodeBlock(ref sourceReference, ref destinationReference, ref decodeTableReference);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryDecodeBlock<T>(ref T source, ref byte destination, ref byte decodeTable) where T : unmanaged
	{
		return typeof(T) == typeof(char)
			? TryDecodeBlock(ref Unsafe.As<T, char>(ref source), ref destination, ref decodeTable)
			: TryDecodeBlock(ref Unsafe.As<T, byte>(ref source), ref destination, ref decodeTable);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteDecodedBlock(ref byte destination, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7)
	{
		Unsafe.Add(ref destination, 0) = (byte)(v0 << 3 | v1 >> 2);
		Unsafe.Add(ref destination, 1) = (byte)(v1 << 6 | v2 << 1 | v3 >> 4);
		Unsafe.Add(ref destination, 2) = (byte)(v3 << 4 | v4 >> 1);
		Unsafe.Add(ref destination, 3) = (byte)(v4 << 7 | v5 << 2 | v6 >> 3);
		Unsafe.Add(ref destination, 4) = (byte)(v6 << 5 | v7);
	}

	private bool TryDecodeTail<T>(ReadOnlySpan<T> source, Span<byte> destination, out int symbolsConsumed, out int bytesWritten) where T : unmanaged
	{
		int buffer = 0;
		int bits = 0;
		int destinationOffset = 0;

		for (int i = 0; i < source.Length; ++i)
		{
			if (!TryGetValue(source[i], out int value))
			{
				symbolsConsumed = i;
				bytesWritten = destinationOffset;
				return false;
			}

			buffer = buffer << 5 | value;
			bits += 5;

			if (bits >= 8)
			{
				// Bits above the pending ones are already written, and the byte cast drops them.
				bits -= 8;
				destination[destinationOffset++] = (byte)(buffer >> bits);
			}
		}

		symbolsConsumed = source.Length;
		bytesWritten = destinationOffset;
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryGetValue<T>(T symbol, out int value) where T : unmanaged
	{
		int index = FromSymbol(symbol);
		byte[] decodeTable = _decodeTable;

		if ((uint)index >= (uint)decodeTable.Length)
		{
			value = InvalidSymbol;
			return false;
		}

		value = decodeTable[index];
		return value is not InvalidSymbol;
	}
}
