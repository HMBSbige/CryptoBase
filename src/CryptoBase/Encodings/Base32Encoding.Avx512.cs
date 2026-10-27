namespace CryptoBase.Encodings;

public sealed partial class Base32Encoding
{
	private const ulong Avx512EncodeShiftControl = 0x00050A0F14191E23UL;

	private static readonly Vector512<byte> Avx512PackIndicesVector = Vector512.Create
	(
		(ReadOnlySpan<byte>)
		[
			4, 3, 2, 1, 0, 40, 40, 40,
			9, 8, 7, 6, 5, 40, 40, 40,
			14, 13, 12, 11, 10, 40, 40, 40,
			19, 18, 17, 16, 15, 40, 40, 40,
			24, 23, 22, 21, 20, 40, 40, 40,
			29, 28, 27, 26, 25, 40, 40, 40,
			34, 33, 32, 31, 30, 40, 40, 40,
			39, 38, 37, 36, 35, 40, 40, 40,
		]
	);

	// Groups 0-7 sit in qwords 0, 2, 4, 6, 1, 3, 5, 7 so the in-lane byte unpacks emit chars in source order.
	private static readonly Vector512<byte> Avx512CharPackIndicesVector = Vector512.Create
	(
		(ReadOnlySpan<byte>)
		[
			4, 3, 2, 1, 0, 40, 40, 40,
			24, 23, 22, 21, 20, 40, 40, 40,
			9, 8, 7, 6, 5, 40, 40, 40,
			29, 28, 27, 26, 25, 40, 40, 40,
			14, 13, 12, 11, 10, 40, 40, 40,
			34, 33, 32, 31, 30, 40, 40, 40,
			19, 18, 17, 16, 15, 40, 40, 40,
			39, 38, 37, 36, 35, 40, 40, 40,
		]
	);

	private static readonly Vector512<byte> Avx512BwPackIndicesVector = Vector512.Create(Vector256.Create((byte)1, 0, 2, 1, 3, 2, 4, 3, 6, 5, 7, 6, 8, 7, 9, 8, 7, 6, 8, 7, 9, 8, 10, 9, 12, 11, 13, 12, 14, 13, 15, 14));
	private static readonly Vector512<byte> Avx512ShiftControlVector = Vector512.Create(Avx512EncodeShiftControl).AsByte();
	private static readonly Vector512<byte> Avx512RfcAlphabetVector = Vector512.Create(Vector256.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8));
	private static readonly Vector512<byte> Avx512HexAlphabetVector = Vector512.Create(Vector256.Create("0123456789ABCDEFGHIJKLMNOPQRSTUV"u8));
	private static readonly Vector512<byte> Avx512RfcDecodeLowVector = CreateDecodeTable(50, 6, 26);
	private static readonly Vector512<byte> Avx512RfcDecodeHighVector = CreateDecodeTable(1, 26, 0);
	private static readonly Vector512<byte> Avx512HexDecodeLowVector = CreateDecodeTable(48, 10, 0);
	private static readonly Vector512<byte> Avx512HexDecodeHighVector = CreateDecodeTable(1, 22, 10);
	private static readonly Vector512<byte> Avx512DecodedPackIndicesVector = Vector512.Create(Vector128.Create((byte)2, 1, 0, 5, 4, 10, 9, 8, 13, 12, 0, 0, 0, 0, 0, 0));
	private static readonly Vector256<byte> Avx512VlRfcDecodeLowVector = Avx512RfcDecodeHighVector.GetLower();
	private static readonly Vector256<byte> Avx512VlRfcDecodeHighVector = Avx512RfcDecodeLowVector.GetUpper();
	private static readonly Vector256<byte> Avx512VlHexDecodeLowVector = Avx512HexDecodeHighVector.GetLower();
	private static readonly Vector256<byte> Avx512VlHexDecodeHighVector = Avx512HexDecodeLowVector.GetUpper();

	private static readonly Vector256<byte> Avx512Vl256PackIndicesVector = Vector256.Create
	(
		(ReadOnlySpan<byte>)
		[
			4, 3, 2, 1, 0, 20, 20, 20,
			9, 8, 7, 6, 5, 20, 20, 20,
			14, 13, 12, 11, 10, 20, 20, 20,
			19, 18, 17, 16, 15, 20, 20, 20,
		]
	);

	// Groups 0-3 sit in qwords 0, 2, 1, 3 so the in-lane byte unpacks emit chars in source order.
	private static readonly Vector256<byte> Avx512Vl256CharPackIndicesVector = Vector256.Create
	(
		(ReadOnlySpan<byte>)
		[
			4, 3, 2, 1, 0, 20, 20, 20,
			14, 13, 12, 11, 10, 20, 20, 20,
			9, 8, 7, 6, 5, 20, 20, 20,
			19, 18, 17, 16, 15, 20, 20, 20,
		]
	);

	private static readonly Vector256<byte> Avx512Vl256ShiftControlVector = Avx512ShiftControlVector.GetLower();
	private static readonly Vector256<byte> Avx512VlRfcAlphabetVector = Avx512RfcAlphabetVector.GetLower();
	private static readonly Vector256<byte> Avx512VlHexAlphabetVector = Avx512HexAlphabetVector.GetLower();

	private static Vector512<byte> CreateDecodeTable(int start, int count, int valueOffset)
	{
		Span<byte> result = stackalloc byte[Vector512<byte>.Count];
		result.Fill(byte.MaxValue);

		for (int i = 0; i < count; ++i)
		{
			result[start + i] = (byte)(valueOffset + i);
		}

		return Vector512.Create(result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static byte GetVectorSymbolMask(byte alphabetKind)
	{
		// The runtime dependency keeps RyuJIT from folding this mask into a memory operand inside hot loops.
		return (byte)(alphabetKind | SymbolMask);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreEncodedCharsUnpacked(Vector512<byte> value, ref char destination)
	{
		ref ushort destinationReference = ref Unsafe.As<char, ushort>(ref destination);
		Avx512BW.UnpackLow(value, Vector512<byte>.Zero).AsUInt16().StoreUnsafe(ref destinationReference);
		Avx512BW.UnpackHigh(value, Vector512<byte>.Zero).AsUInt16().StoreUnsafe(ref destinationReference, 32);
	}

	// For char, value must already hold the groups in the qword order StoreEncodedCharsUnpacked expects, which the char pack indices produce.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreUnpackedSymbols<T>(Vector512<byte> value, ref T destination) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			value.StoreUnsafe(ref Unsafe.As<T, byte>(ref destination));
			return;
		}

		StoreEncodedCharsUnpacked(value, ref Unsafe.As<T, char>(ref destination));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> MapSymbols(Vector512<byte> value, Vector512<byte> threshold, Vector512<byte> first, Vector512<byte> second)
	{
		Vector512<byte> mask = Vector512.GreaterThan(value, threshold);
		return value + Vector512.ConditionalSelect(mask, second, first);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> EncodeEight(ref byte source, Vector512<byte> threshold, Vector512<byte> first, Vector512<byte> second)
	{
		Vector256<byte> lower = Vector256.Create(Vector128.LoadUnsafe(ref source), Vector128.LoadUnsafe(ref source, 4));
		Vector256<byte> upper = Vector256.Create(Vector128.LoadUnsafe(ref source, 20), Vector128.LoadUnsafe(ref source, 24));
		Vector512<ulong> windows = Avx512BW.Shuffle(lower.ToVector512Unsafe().WithUpper(upper), Avx512BwPackIndicesVector).AsUInt64();
		Vector512<ushort> even = Avx512BW.MultiplyHigh((windows & Vector512.Create(0x03e00f803e00f800UL)).AsUInt16(), Vector512.Create(0x0800020000800020UL).AsUInt16());
		Vector512<ushort> odd = (windows & Vector512.Create(0x001f007c01f007c0UL)).AsUInt16() * Vector512.Create(0x0100004000100004UL).AsUInt16();
		return MapSymbols((even | odd).AsByte(), threshold, first, second);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> EncodeVbmi(Vector512<byte> input, Vector512<byte> packIndices, Vector512<byte> shiftControl, Vector512<byte> symbolMask, Vector512<byte> alphabet)
	{
		Vector512<byte> packed = Avx512Vbmi.PermuteVar64x8(input, packIndices);
		Vector512<byte> symbols = Avx512Vbmi.MultiShift(shiftControl, packed.AsUInt64()) & symbolMask;
		return Avx512Vbmi.PermuteVar64x8(alphabet, symbols);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> EncodeVbmiVl256(Vector256<byte> input, Vector256<byte> packIndices, Vector256<byte> shiftControl, Vector256<byte> symbolMask, Vector256<byte> alphabet)
	{
		Vector256<byte> packed = Avx512Vbmi.VL.PermuteVar32x8(input, packIndices);
		Vector256<byte> symbols = Avx512Vbmi.VL.MultiShift(shiftControl, packed.AsUInt64()) & symbolMask;
		return Avx512Vbmi.VL.PermuteVar32x8(alphabet, symbols);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeVbmiVl128(Vector128<byte> input, Vector128<byte> packIndices, Vector128<byte> shiftControl, Vector128<byte> symbolMask, Vector128<byte> alphabetLow, Vector128<byte> alphabetHigh)
	{
		Vector128<byte> packed = Vector128.ShuffleNative(input, packIndices);
		Vector128<byte> symbols = Avx512Vbmi.VL.MultiShift(shiftControl, packed.AsUInt64()) & symbolMask;
		return Avx512Vbmi.VL.PermuteVar16x8x2(alphabetLow, symbols, alphabetHigh);
	}

	// A full-width load reads 24 or 12 bytes past its blocks, into filler lanes that the symbol mask drops. The kernels load at full width while that overread stays inside the source, that is while five or three more blocks follow, and the last blocks exactly.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> LoadEightBlocks(ref byte source)
	{
		return Vector256.LoadUnsafe(ref source).ToVector512Unsafe().WithUpper(Vector256.CreateScalar(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 32))).AsByte());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> LoadFourBlocks(ref byte source)
	{
		return Vector128.LoadUnsafe(ref source).ToVector256Unsafe().WithUpper(Vector128.CreateScalar(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 16))).AsByte());
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeAvx512Bw<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector512<byte> threshold = Vector512.Create(thresholdValue);
		Vector512<byte> first = Vector512.Create(firstValue);
		Vector512<byte> second = Vector512.Create(secondValue);
		int blockCount = GetEncodeBlockCount(source.Length, destination.Length, 8);
		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref T destinationPointer = ref MemoryMarshal.GetReference(destination);
		int vectorCount = blockCount >> 3;

		for (int i = 0; i < vectorCount; ++i)
		{
			StoreSymbols(EncodeEight(ref sourcePointer, threshold, first, second), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		if ((blockCount & 7) is not 0)
		{
			int lastOctet = blockCount - 8;
			StoreSymbols(EncodeEight(ref Unsafe.Add(ref MemoryMarshal.GetReference(source), lastOctet * InputBytesPerBlock), threshold, first, second), ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), lastOctet * OutputSymbolsPerBlock));
		}

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeAvx512Vbmi<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(alphabetKind));
		Vector512<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512HexAlphabetVector : Avx512RfcAlphabetVector;
		return EncodeBlocksAvx512Vbmi(source, destination, symbolMask, alphabet, typeof(T) == typeof(char) ? Avx512CharPackIndicesVector : Avx512PackIndicesVector, Avx512ShiftControlVector);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private int EncodeAvx512VbmiCustom<T>(ReadOnlySpan<byte> source, Span<T> destination) where T : unmanaged
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(_alphabetKind));
		Vector512<byte> alphabet = Vector512.Create(Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet)));

		if (typeof(T) != typeof(char))
		{
			return EncodeBlocksAvx512Vbmi(source, destination, symbolMask, alphabet, Avx512PackIndicesVector, Avx512ShiftControlVector);
		}

		// Local constants avoid the class-initialization slow path and register spills that RyuJIT otherwise emits for static vectors in this instance hot path. Same layout as Avx512CharPackIndicesVector.
		Vector512<byte> packIndices = Vector512.Create
		(
			Vector256.Create
			(
				Vector128.Create((byte)4, 3, 2, 1, 0, 40, 40, 40, 24, 23, 22, 21, 20, 40, 40, 40),
				Vector128.Create((byte)9, 8, 7, 6, 5, 40, 40, 40, 29, 28, 27, 26, 25, 40, 40, 40)
			),
			Vector256.Create
			(
				Vector128.Create((byte)14, 13, 12, 11, 10, 40, 40, 40, 34, 33, 32, 31, 30, 40, 40, 40),
				Vector128.Create((byte)19, 18, 17, 16, 15, 40, 40, 40, 39, 38, 37, 36, 35, 40, 40, 40)
			)
		);
		Vector512<byte> shiftControl = Vector512.Create(Avx512EncodeShiftControl).AsByte();
		return EncodeBlocksAvx512Vbmi(source, destination, symbolMask, alphabet, packIndices, shiftControl);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int EncodeAvx512VbmiVl256<T>(ReadOnlySpan<byte> source, Span<T> destination, byte alphabetKind) where T : unmanaged
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(alphabetKind));
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		return EncodeBlocksAvx512VbmiVl256(source, destination, symbolMask, alphabet);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private int EncodeAvx512VbmiVl256Custom<T>(ReadOnlySpan<byte> source, Span<T> destination) where T : unmanaged
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(_alphabetKind));
		Vector256<byte> alphabet = Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet));
		return EncodeBlocksAvx512VbmiVl256(source, destination, symbolMask, alphabet);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int EncodeBlocksAvx512Vbmi<T>(ReadOnlySpan<byte> source, Span<T> destination, Vector512<byte> symbolMask, Vector512<byte> alphabet, Vector512<byte> packIndices, Vector512<byte> shiftControl) where T : unmanaged
	{
		int blockCount = Math.Min(source.Length / InputBytesPerBlock, destination.Length / OutputSymbolsPerBlock);

		if (blockCount < 8)
		{
			return 0;
		}

		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref T destinationPointer = ref MemoryMarshal.GetReference(destination);
		int vectorCount = blockCount - 5 >> 3;
		int pairCount = vectorCount >> 1;
		const int stride = 80;
		int prefetchPairs = StreamPrefetch.Iterations(pairCount, stride);

		for (int i = 0; i < pairCount; ++i)
		{
			if (i < prefetchPairs)
			{
				StreamPrefetch.Bytes(ref sourcePointer, stride);
			}

			Vector512<byte> firstInput = Vector512.LoadUnsafe(ref sourcePointer);
			Vector512<byte> secondInput = Vector512.LoadUnsafe(ref sourcePointer, 40);
			Vector512<byte> firstPacked = Avx512Vbmi.PermuteVar64x8(firstInput, packIndices);
			Vector512<byte> secondPacked = Avx512Vbmi.PermuteVar64x8(secondInput, packIndices);
			Vector512<byte> firstSymbols = Avx512Vbmi.MultiShift(shiftControl, firstPacked.AsUInt64()) & symbolMask;
			Vector512<byte> secondSymbols = Avx512Vbmi.MultiShift(shiftControl, secondPacked.AsUInt64()) & symbolMask;
			StoreUnpackedSymbols(Avx512Vbmi.PermuteVar64x8(alphabet, firstSymbols), ref destinationPointer);
			StoreUnpackedSymbols(Avx512Vbmi.PermuteVar64x8(alphabet, secondSymbols), ref Unsafe.Add(ref destinationPointer, 64));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, stride);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 128);
		}

		if ((vectorCount & 1) is not 0)
		{
			StoreUnpackedSymbols(EncodeVbmi(Vector512.LoadUnsafe(ref sourcePointer), packIndices, shiftControl, symbolMask, alphabet), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		int lastOctet = blockCount - 8;
		ref byte lastOctetSource = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), lastOctet * InputBytesPerBlock);

		if (Unsafe.IsAddressGreaterThan(ref lastOctetSource, ref sourcePointer))
		{
			StoreUnpackedSymbols(EncodeVbmi(LoadEightBlocks(ref sourcePointer), packIndices, shiftControl, symbolMask, alphabet), ref destinationPointer);
		}

		StoreUnpackedSymbols(EncodeVbmi(LoadEightBlocks(ref lastOctetSource), packIndices, shiftControl, symbolMask, alphabet), ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), lastOctet * OutputSymbolsPerBlock));

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int EncodeBlocksAvx512VbmiVl256<T>(ReadOnlySpan<byte> source, Span<T> destination, Vector256<byte> symbolMask, Vector256<byte> alphabet) where T : unmanaged
	{
		int blockCount = Math.Min(source.Length / InputBytesPerBlock, destination.Length / OutputSymbolsPerBlock);

		if (blockCount < 4)
		{
			return 0;
		}

		Vector256<byte> packIndices = typeof(T) == typeof(char) ? Avx512Vl256CharPackIndicesVector : Avx512Vl256PackIndicesVector;
		ref byte sourcePointer = ref MemoryMarshal.GetReference(source);
		ref T destinationPointer = ref MemoryMarshal.GetReference(destination);
		int vectorCount = blockCount - 3 >> 2;
		int pairCount = vectorCount >> 1;
		const int stride = 40;
		int prefetchPairs = StreamPrefetch.Iterations(pairCount, stride);

		for (int i = 0; i < pairCount; ++i)
		{
			if (i < prefetchPairs)
			{
				StreamPrefetch.Bytes(ref sourcePointer, stride);
			}

			Vector256<byte> firstInput = Vector256.LoadUnsafe(ref sourcePointer);
			Vector256<byte> secondInput = Vector256.LoadUnsafe(ref sourcePointer, 20);
			Vector256<byte> firstOutput = EncodeVbmiVl256(firstInput, packIndices, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			Vector256<byte> secondOutput = EncodeVbmiVl256(secondInput, packIndices, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			StoreSymbols(firstOutput, ref destinationPointer);
			StoreSymbols(secondOutput, ref Unsafe.Add(ref destinationPointer, 32));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, stride);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		if ((vectorCount & 1) is not 0)
		{
			StoreSymbols(EncodeVbmiVl256(Vector256.LoadUnsafe(ref sourcePointer), packIndices, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		int lastQuad = blockCount - 4;
		ref byte lastQuadSource = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), lastQuad * InputBytesPerBlock);

		if (Unsafe.IsAddressGreaterThan(ref lastQuadSource, ref sourcePointer))
		{
			StoreSymbols(EncodeVbmiVl256(LoadFourBlocks(ref sourcePointer), packIndices, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref destinationPointer);
		}

		StoreSymbols(EncodeVbmiVl256(LoadFourBlocks(ref lastQuadSource), packIndices, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref Unsafe.Add(ref MemoryMarshal.GetReference(destination), lastQuad * OutputSymbolsPerBlock));

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> GetShortAlphabet(byte alphabetKind)
	{
		return alphabetKind is Rfc4648HexAlphabetKind ? Vector256.Create("0123456789ABCDEFGHIJKLMNOPQRSTUV"u8) : Vector256.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8);
	}

	// EncodeCore inlines this, custom alphabets included, so its tables are literals rather than the static vectors: a process that only uses custom alphabets never initializes the class statics, and EncodeCore would then keep the initialization helper calls, with the vectors live across them in callee-saved registers that every call saves and restores.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncodeVbmiVl128Short(ref byte source, nuint offset, Vector256<byte> alphabet)
	{
		Vector128<byte> symbolMask = Vector128.Create((byte)SymbolMask);
		Vector128<byte> input = Vector128.CreateScalar(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, offset))).AsUInt16().WithElement(4, Unsafe.ReadUnaligned<ushort>(ref Unsafe.Add(ref source, offset + 8))).AsByte();
		Vector128<byte> packIndices = Vector128.Create((byte)4, 3, 2, 1, 0, 10, 10, 10, 9, 8, 7, 6, 5, 10, 10, 10);
		Vector128<byte> shiftControl = Vector128.Create(Avx512EncodeShiftControl).AsByte();
		return EncodeVbmiVl128(input, packIndices, shiftControl, symbolMask, alphabet.GetLower(), alphabet.GetUpper());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int EncodeAvx512VbmiVl128Short<T>(ReadOnlySpan<byte> source, Span<T> destination, Vector256<byte> alphabet) where T : unmanaged
	{
		ref byte sourceReference = ref MemoryMarshal.GetReference(source);
		ref T destinationReference = ref MemoryMarshal.GetReference(destination);
		int blockCount = GetEncodeShortBlockCount(source.Length, destination.Length);
		StoreSymbols(EncodeVbmiVl128Short(ref sourceReference, 0, alphabet), ref destinationReference);

		if (blockCount is 3)
		{
			StoreSymbols(EncodeVbmiVl128Short(ref sourceReference, InputBytesPerBlock, alphabet), ref Unsafe.Add(ref destinationReference, OutputSymbolsPerBlock));
		}

		return blockCount * InputBytesPerBlock;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> DecodeEight(Vector512<byte> input, Vector512<byte> deltaCheck, Vector512<byte> deltaRebase, Vector512<byte> nibbleMask, Vector512<sbyte> lowerBound, out Vector512<byte> invalidMask)
	{
		Vector512<byte> hashKey = (input.AsUInt32() >>> 4).AsByte() & nibbleMask;
		Vector512<byte> check = input + Avx512BW.Shuffle(deltaCheck, hashKey);
		invalidMask = check | Vector512.GreaterThan(lowerBound, input.AsSByte()).AsByte();
		return input + Avx512BW.Shuffle(deltaRebase, hashKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsValidAvx512(Vector512<byte> invalidMask)
	{
		return invalidMask.ExtractMostSignificantBits() is 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> PackDecoded(Vector512<byte> values, Vector512<byte> packIndices)
	{
		Vector512<short> pairs = Avx512BW.MultiplyAddAdjacent(values, Vector512.Create(0x01200120).AsSByte());
		Vector512<short> multipliers = Vector512.Create(0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400, 0x00104000, 0x00010400).AsInt16();
		Vector512<int> quads = Avx512BW.MultiplyAddAdjacent(pairs, multipliers);
		Vector512<byte> merged = (quads.AsUInt64() | quads.AsUInt64() >>> 48).AsByte();
		return Avx512BW.Shuffle(merged, packIndices);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreDecoded(Vector512<byte> packed, ref byte destination)
	{
		Vector256<byte> lower = packed.GetLower();
		Vector256<byte> upper = packed.GetUpper();
		lower.GetLower().StoreUnsafe(ref destination);
		lower.GetUpper().StoreUnsafe(ref Unsafe.Add(ref destination, 10));
		upper.GetLower().StoreUnsafe(ref Unsafe.Add(ref destination, 20));
		StoreDecoded(upper.GetUpper(), ref Unsafe.Add(ref destination, 30));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreDecodedOverlapping(Vector512<byte> packed, ref byte destination)
	{
		Vector256<byte> lower = packed.GetLower();
		Vector256<byte> upper = packed.GetUpper();
		lower.GetLower().StoreUnsafe(ref destination);
		lower.GetUpper().StoreUnsafe(ref Unsafe.Add(ref destination, 10));
		upper.GetLower().StoreUnsafe(ref Unsafe.Add(ref destination, 20));
		upper.GetUpper().StoreUnsafe(ref Unsafe.Add(ref destination, 30));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> LookupVbmiVl256(Vector256<byte> input, Vector256<byte> low, Vector256<byte> high)
	{
		// The 256-bit VPERMI2B only reads index bits 5:0, so a byte outside 0x20-0x5F would alias an entry inside that window. Clamping maps such bytes to ' ' or '_', which are invalid in both alphabets.
		Vector256<byte> index = Vector256.Min(Vector256.Max(input, Vector256.Create((byte)' ')), Vector256.Create((byte)'_'));
		return Avx512Vbmi.VL.PermuteVar32x8x2(low, index, high);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int DecodeAvx512VbmiVl256<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind) where T : unmanaged
	{
		Vector256<byte> low = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeLowVector : Avx512VlRfcDecodeLowVector;
		Vector256<byte> high = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeHighVector : Avx512VlRfcDecodeHighVector;
		int blockCount = Math.Min(fullLength >> 5, destination.Length / 20);
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

			Vector256<byte> firstInput = LoadSymbols256(ref sourcePointer);
			Vector256<byte> secondInput = LoadSymbols256(ref Unsafe.Add(ref sourcePointer, 32));
			Vector256<byte> first = LookupVbmiVl256(firstInput, low, high);
			Vector256<byte> second = LookupVbmiVl256(secondInput, low, high);

			if ((first | second).ExtractMostSignificantBits() is not 0)
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
			Vector256<byte> values = LookupVbmiVl256(LoadSymbols256(ref sourcePointer), low, high);

			if (values.ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int DecodeAvx512<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind) where T : unmanaged
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector512<byte> deltaCheck = Vector512.Broadcast(deltaCheck128);
		Vector512<byte> deltaRebase = Vector512.Broadcast(deltaRebase128);
		Vector512<byte> nibbleMask = Vector512.Create((byte)0x0f);
		Vector512<sbyte> lowerBound = Vector512.Create((sbyte)mapLowerBound);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref T sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int pairCount = blockCount >> 1;
		const int stride = 256;
		int prefetchPairs = StreamPrefetch.Iterations(pairCount, stride);
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if (typeof(T) == typeof(char) && i < prefetchPairs)
			{
				StreamPrefetch.Bytes(ref sourcePointer, stride);
			}

			Vector512<byte> first = DecodeEight(LoadSymbols512(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> firstInvalidMask);
			Vector512<byte> second = DecodeEight(LoadSymbols512(ref Unsafe.Add(ref sourcePointer, 64)), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> secondInvalidMask);

			if (!IsValidAvx512(firstInvalidMask | secondInvalidMask))
			{
				break;
			}

			StoreDecodedOverlapping(PackDecoded(first, packIndices), ref destinationPointer);
			StoreDecoded(PackDecoded(second, packIndices), ref Unsafe.Add(ref destinationPointer, 40));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 128);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 80);
			processedBlocks += 2;
		}

		if (processedBlocks == pairCount * 2 && (blockCount & 1) is not 0)
		{
			Vector512<byte> values = DecodeEight(LoadSymbols512(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> invalidMask);

			if (IsValidAvx512(invalidMask))
			{
				StoreDecoded(PackDecoded(values, packIndices), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 64;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GetAvx512DecodeTables(byte alphabetKind, out Vector512<byte> low, out Vector512<byte> high)
	{
		if (alphabetKind is CustomAlphabetKind)
		{
			ref byte decodeTable = ref MemoryMarshal.GetArrayDataReference(_decodeTable);
			low = Vector512.LoadUnsafe(ref decodeTable);
			high = Vector512.LoadUnsafe(ref decodeTable, 64);
		}
		else
		{
			low = alphabetKind is Rfc4648HexAlphabetKind ? Avx512HexDecodeLowVector : Avx512RfcDecodeLowVector;
			high = alphabetKind is Rfc4648HexAlphabetKind ? Avx512HexDecodeHighVector : Avx512RfcDecodeHighVector;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private int DecodeAvx512Vbmi<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind) where T : unmanaged
	{
		GetAvx512DecodeTables(alphabetKind, out Vector512<byte> low, out Vector512<byte> high);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref T sourcePointer = ref MemoryMarshal.GetReference(source);
		ref byte destinationPointer = ref MemoryMarshal.GetReference(destination);
		int pairCount = blockCount >> 1;
		const int stride = 256;
		int prefetchPairs = StreamPrefetch.Iterations(pairCount, stride);
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if (typeof(T) == typeof(char) && i < prefetchPairs)
			{
				StreamPrefetch.Bytes(ref sourcePointer, stride);
			}

			Vector512<byte> firstInput = LoadSymbols512(ref sourcePointer);
			Vector512<byte> secondInput = LoadSymbols512(ref Unsafe.Add(ref sourcePointer, 64));
			Vector512<byte> first = Avx512Vbmi.PermuteVar64x8x2(low, firstInput, high);
			Vector512<byte> second = Avx512Vbmi.PermuteVar64x8x2(low, secondInput, high);

			// VPERMI2B ignores index bit 7, so the input high bit must be tested to reject non-ASCII.
			if ((firstInput | first | secondInput | second).ExtractMostSignificantBits() is not 0)
			{
				break;
			}

			StoreDecodedOverlapping(PackDecoded(first, packIndices), ref destinationPointer);
			StoreDecoded(PackDecoded(second, packIndices), ref Unsafe.Add(ref destinationPointer, 40));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 128);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 80);
			processedBlocks += 2;
		}

		if (processedBlocks == pairCount * 2 && (blockCount & 1) is not 0)
		{
			Vector512<byte> input = LoadSymbols512(ref sourcePointer);
			Vector512<byte> values = Avx512Vbmi.PermuteVar64x8x2(low, input, high);

			if ((input | values).ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values, packIndices), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 64;
	}
}
