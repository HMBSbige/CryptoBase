namespace CryptoBase.DataFormatExtensions;

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

	private static readonly Vector512<byte> Avx512ShiftControlVector = Vector512.Create(Avx512EncodeShiftControl).AsByte();
	private static readonly Vector512<byte> Avx512RfcAlphabetVector = Vector512.Create(Vector256.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"u8));
	private static readonly Vector512<byte> Avx512HexAlphabetVector = Vector512.Create(Vector256.Create("0123456789ABCDEFGHIJKLMNOPQRSTUV"u8));
	private static readonly Vector512<byte> Avx512EncodeLoadMask = Vector512.Create(Vector256.Create(byte.MaxValue), Vector256.Create(Vector128.Create(ulong.MaxValue, 0UL).AsByte(), Vector128<byte>.Zero));
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

	private static readonly Vector128<byte> Avx512Vl128PackIndicesVector = Vector128.Create
	(
		(ReadOnlySpan<byte>)
		[
			4, 3, 2, 1, 0, 10, 10, 10,
			9, 8, 7, 6, 5, 10, 10, 10,
		]
	);

	private static readonly Vector256<byte> Avx512Vl256ShiftControlVector = Avx512ShiftControlVector.GetLower();
	private static readonly Vector128<byte> Avx512Vl128ShiftControlVector = Avx512Vl256ShiftControlVector.GetLower();
	private static readonly Vector256<byte> Avx512VlRfcAlphabetVector = Avx512RfcAlphabetVector.GetLower();
	private static readonly Vector256<byte> Avx512VlHexAlphabetVector = Avx512HexAlphabetVector.GetLower();
	private static readonly Vector256<byte> Avx512Vl256EncodeLoadMask = Vector256.Create(Vector128.Create(byte.MaxValue), Vector128.Create(uint.MaxValue, 0U, 0U, 0U).AsByte());
	private static readonly Vector128<byte> Avx512Vl128EncodeLoadMask = Vector128.Create(ulong.MaxValue, ushort.MaxValue).AsByte();

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
	private static Vector512<byte> MapSymbols(Vector512<byte> value, Vector512<byte> threshold, Vector512<byte> first, Vector512<byte> second)
	{
		Vector512<byte> mask = Vector512.GreaterThan(value, threshold);
		return value + Vector512.ConditionalSelect(mask, second, first);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> EncodeEight(Vector512<ulong> value, Vector512<byte> threshold, Vector512<byte> first, Vector512<byte> second)
	{
		Vector512<ulong> mask = Vector512.Create((ulong)SymbolMask);
		Vector512<ulong> result = value >>> 35 & mask;
		Vector512<ulong> next = (value >>> 30 & mask) << 8;
		Vector512<ulong> later = (value >>> 25 & mask) << 16;
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> PackEightFast(ref byte source)
	{
		return Vector512.Create
		(
			Pack5Fast(ref source), Pack5Fast(ref Unsafe.Add(ref source, 5)),
			Pack5Fast(ref Unsafe.Add(ref source, 10)), Pack5Fast(ref Unsafe.Add(ref source, 15)),
			Pack5Fast(ref Unsafe.Add(ref source, 20)), Pack5Fast(ref Unsafe.Add(ref source, 25)),
			Pack5Fast(ref Unsafe.Add(ref source, 30)), Pack5Fast(ref Unsafe.Add(ref source, 35))
		);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> PackEight(ref byte source)
	{
		return Vector512.Create
		(
			Pack5(ref source), Pack5(ref Unsafe.Add(ref source, 5)),
			Pack5(ref Unsafe.Add(ref source, 10)), Pack5(ref Unsafe.Add(ref source, 15)),
			Pack5(ref Unsafe.Add(ref source, 20)), Pack5(ref Unsafe.Add(ref source, 25)),
			Pack5(ref Unsafe.Add(ref source, 30)), Pack5(ref Unsafe.Add(ref source, 35))
		);
	}

	private static int EncodeUtf8Avx512Bw(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector512<byte> threshold = Vector512.Create(thresholdValue);
		Vector512<byte> first = Vector512.Create(firstValue);
		Vector512<byte> second = Vector512.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 40 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 40, destinationRemaining / 64)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			EncodeEight(PackEightFast(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		int consumed = blockCount * 40;

		if (sourceRemaining - consumed >= 40 && destinationRemaining - blockCount * 64 >= 64)
		{
			EncodeEight(PackEight(ref sourcePointer), threshold, first, second).StoreUnsafe(ref destinationPointer);
			consumed += 40;
		}

		return consumed;
	}

	private static int EncodeCharsAvx512Bw(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		GetEncodeMap(alphabetKind, out byte thresholdValue, out byte firstValue, out byte secondValue);
		Vector512<byte> threshold = Vector512.Create(thresholdValue);
		Vector512<byte> first = Vector512.Create(firstValue);
		Vector512<byte> second = Vector512.Create(secondValue);
		int sourceRemaining = source.Length;
		int destinationRemaining = destination.Length;
		int blockCount = sourceRemaining >= 40 + Pack5FastOverReadBytes
			? Math.Min((sourceRemaining - Pack5FastOverReadBytes) / 40, destinationRemaining / 64)
			: 0;
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();

		for (int i = 0; i < blockCount; ++i)
		{
			StoreEncodedChars(EncodeEight(PackEightFast(ref sourcePointer), threshold, first, second), ref destinationPointer);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		int consumed = blockCount * 40;

		if (sourceRemaining - consumed >= 40 && destinationRemaining - blockCount * 64 >= 64)
		{
			StoreEncodedChars(EncodeEight(PackEight(ref sourcePointer), threshold, first, second), ref destinationPointer);
			consumed += 40;
		}

		return consumed;
	}

	private static unsafe int EncodeUtf8Avx512Vbmi(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(alphabetKind));
		Vector512<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512HexAlphabetVector : Avx512RfcAlphabetVector;
		int blockCount = Math.Min(source.Length / 40, destination.Length / 64);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> firstInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> secondInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 40)), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 80);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 128);
			Vector512<byte> firstPacked = Avx512Vbmi.PermuteVar64x8(firstInput, Avx512PackIndicesVector);
			Vector512<byte> secondPacked = Avx512Vbmi.PermuteVar64x8(secondInput, Avx512PackIndicesVector);
			Vector512<byte> firstSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, firstPacked.AsUInt64());
			Vector512<byte> secondSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, secondPacked.AsUInt64());
			firstSymbols &= symbolMask;
			secondSymbols &= symbolMask;
			Vector512<byte> firstOutput = Avx512Vbmi.PermuteVar64x8(alphabet, firstSymbols);
			Vector512<byte> secondOutput = Avx512Vbmi.PermuteVar64x8(alphabet, secondSymbols);
			firstOutput.StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 128));
			secondOutput.StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 64));
		}

		if ((blockCount & 1) is not 0)
		{
			Vector512<byte> input = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> packed = Avx512Vbmi.PermuteVar64x8(input, Avx512PackIndicesVector);
			Vector512<byte> symbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, packed.AsUInt64()) & symbolMask;
			Avx512Vbmi.PermuteVar64x8(alphabet, symbols).StoreUnsafe(ref destinationPointer);
		}

		return blockCount * 40;
	}

	private static unsafe int EncodeCharsAvx512Vbmi(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(alphabetKind));
		Vector512<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512HexAlphabetVector : Avx512RfcAlphabetVector;
		int blockCount = Math.Min(source.Length / 40, destination.Length / 64);
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> firstInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> secondInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 40)), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> firstPacked = Avx512Vbmi.PermuteVar64x8(firstInput, Avx512PackIndicesVector);
			Vector512<byte> secondPacked = Avx512Vbmi.PermuteVar64x8(secondInput, Avx512PackIndicesVector);
			Vector512<byte> firstSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, firstPacked.AsUInt64()) & symbolMask;
			Vector512<byte> secondSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, secondPacked.AsUInt64()) & symbolMask;
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, firstSymbols), ref destinationPointer);
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, secondSymbols), ref Unsafe.Add(ref destinationPointer, 64));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 80);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 128);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector512<byte> input = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> packed = Avx512Vbmi.PermuteVar64x8(input, Avx512PackIndicesVector);
			Vector512<byte> symbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, packed.AsUInt64()) & symbolMask;
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, symbols), ref destinationPointer);
		}

		return blockCount * 40;
	}

	private static unsafe int EncodeUtf8Avx512VbmiVl256(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(alphabetKind));
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		int blockCount = Math.Min(source.Length / 20, destination.Length / 32);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			Vector256<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 20)), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
			Vector256<byte> firstOutput = EncodeVbmiVl256(firstInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			Vector256<byte> secondOutput = EncodeVbmiVl256(secondInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			firstOutput.StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 64));
			secondOutput.StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 32));
		}

		if ((blockCount & 1) is not 0)
		{
			Vector256<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			EncodeVbmiVl256(input, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet).StoreUnsafe(ref destinationPointer);
		}

		return blockCount * 20;
	}

	private static unsafe int EncodeCharsAvx512VbmiVl256(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(alphabetKind));
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		int blockCount = Math.Min(source.Length / 20, destination.Length / 32);
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			Vector256<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 20)), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			Vector256<byte> firstOutput = EncodeVbmiVl256(firstInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			Vector256<byte> secondOutput = EncodeVbmiVl256(secondInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet);
			StoreEncodedChars(firstOutput, ref destinationPointer);
			StoreEncodedChars(secondOutput, ref Unsafe.Add(ref destinationPointer, 32));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector256<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			StoreEncodedChars(EncodeVbmiVl256(input, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref destinationPointer);
		}

		return blockCount * 20;
	}

	private unsafe int EncodeUtf8Avx512VbmiCustom(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(_alphabetKind));
		Vector512<byte> alphabet = Vector512.Create(Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet)));
		int blockCount = Math.Min(source.Length / 40, destination.Length / 64);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> firstInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> secondInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 40)), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 80);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 128);
			Vector512<byte> firstPacked = Avx512Vbmi.PermuteVar64x8(firstInput, Avx512PackIndicesVector);
			Vector512<byte> secondPacked = Avx512Vbmi.PermuteVar64x8(secondInput, Avx512PackIndicesVector);
			Vector512<byte> firstSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, firstPacked.AsUInt64()) & symbolMask;
			Vector512<byte> secondSymbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, secondPacked.AsUInt64()) & symbolMask;
			Avx512Vbmi.PermuteVar64x8(alphabet, firstSymbols).StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 128));
			Avx512Vbmi.PermuteVar64x8(alphabet, secondSymbols).StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 64));
		}

		if ((blockCount & 1) is not 0)
		{
			Vector512<byte> input = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512EncodeLoadMask, Vector512<byte>.Zero);
			Vector512<byte> packed = Avx512Vbmi.PermuteVar64x8(input, Avx512PackIndicesVector);
			Vector512<byte> symbols = Avx512Vbmi.MultiShift(Avx512ShiftControlVector, packed.AsUInt64()) & symbolMask;
			Avx512Vbmi.PermuteVar64x8(alphabet, symbols).StoreUnsafe(ref destinationPointer);
		}

		return blockCount * 40;
	}

	private unsafe int EncodeCharsAvx512VbmiCustom(ReadOnlySpan<byte> source, Span<char> destination)
	{
		Vector512<byte> symbolMask = Vector512.Create(GetVectorSymbolMask(_alphabetKind));
		Vector512<byte> alphabet = Vector512.Create(Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet)));
		// Local constants avoid the class-initialization slow path and register spills
		// that RyuJIT otherwise emits for static vectors in this instance hot path.
		Vector512<byte> loadMask = Vector512.Create
		(
			Vector256.Create(byte.MaxValue),
			Vector256.Create(Vector128.Create(ulong.MaxValue, 0UL).AsByte(), Vector128<byte>.Zero)
		);
		Vector512<byte> packIndices = Vector512.Create
		(
			Vector256.Create
			(
				Vector128.Create((byte)4, 3, 2, 1, 0, 40, 40, 40, 9, 8, 7, 6, 5, 40, 40, 40),
				Vector128.Create((byte)14, 13, 12, 11, 10, 40, 40, 40, 19, 18, 17, 16, 15, 40, 40, 40)
			),
			Vector256.Create
			(
				Vector128.Create((byte)24, 23, 22, 21, 20, 40, 40, 40, 29, 28, 27, 26, 25, 40, 40, 40),
				Vector128.Create((byte)34, 33, 32, 31, 30, 40, 40, 40, 39, 38, 37, 36, 35, 40, 40, 40)
			)
		);
		Vector512<byte> shiftControl = Vector512.Create(Avx512EncodeShiftControl).AsByte();
		int blockCount = Math.Min(source.Length / 40, destination.Length / 64);
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> firstInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), loadMask, Vector512<byte>.Zero);
			Vector512<byte> secondInput = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 40)), loadMask, Vector512<byte>.Zero);
			Vector512<byte> firstPacked = Avx512Vbmi.PermuteVar64x8(firstInput, packIndices);
			Vector512<byte> secondPacked = Avx512Vbmi.PermuteVar64x8(secondInput, packIndices);
			Vector512<byte> firstSymbols = Avx512Vbmi.MultiShift(shiftControl, firstPacked.AsUInt64()) & symbolMask;
			Vector512<byte> secondSymbols = Avx512Vbmi.MultiShift(shiftControl, secondPacked.AsUInt64()) & symbolMask;
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, firstSymbols), ref destinationPointer);
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, secondSymbols), ref Unsafe.Add(ref destinationPointer, 64));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 80);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 128);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector512<byte> input = Avx512BW.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), loadMask, Vector512<byte>.Zero);
			Vector512<byte> packed = Avx512Vbmi.PermuteVar64x8(input, packIndices);
			Vector512<byte> symbols = Avx512Vbmi.MultiShift(shiftControl, packed.AsUInt64()) & symbolMask;
			StoreEncodedChars(Avx512Vbmi.PermuteVar64x8(alphabet, symbols), ref destinationPointer);
		}

		return blockCount * 40;
	}

	private unsafe int EncodeUtf8Avx512VbmiVl256Custom(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(_alphabetKind));
		Vector256<byte> alphabet = Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet));
		int blockCount = Math.Min(source.Length / 20, destination.Length / 32);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			Vector256<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 20)), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
			EncodeVbmiVl256(firstInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet).StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 64));
			EncodeVbmiVl256(secondInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet).StoreUnsafe(ref Unsafe.Subtract(ref destinationPointer, 32));
		}

		if ((blockCount & 1) is not 0)
		{
			Vector256<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			EncodeVbmiVl256(input, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet).StoreUnsafe(ref destinationPointer);
		}

		return blockCount * 20;
	}

	private unsafe int EncodeCharsAvx512VbmiVl256Custom(ReadOnlySpan<byte> source, Span<char> destination)
	{
		Vector256<byte> symbolMask = Vector256.Create(GetVectorSymbolMask(_alphabetKind));
		Vector256<byte> alphabet = Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(_alphabet));
		int blockCount = Math.Min(source.Length / 20, destination.Length / 32);
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			Vector256<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 20)), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			StoreEncodedChars(EncodeVbmiVl256(firstInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref destinationPointer);
			StoreEncodedChars(EncodeVbmiVl256(secondInput, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref Unsafe.Add(ref destinationPointer, 32));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 40);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 64);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector256<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl256EncodeLoadMask, Vector256<byte>.Zero);
			StoreEncodedChars(EncodeVbmiVl256(input, Avx512Vl256PackIndicesVector, Avx512Vl256ShiftControlVector, symbolMask, alphabet), ref destinationPointer);
		}

		return blockCount * 20;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe Vector128<byte> EncodeAvx512VbmiVl128CustomSingle(ReadOnlySpan<byte> source, byte[] alphabetBytes)
	{
		// Keep the complete block self-contained so it can inline without static-vector initialization checks.
		Vector128<byte> symbolMask = Vector128.Create((byte)SymbolMask);
		Vector256<byte> alphabet = Vector256.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(alphabetBytes));
		Vector128<byte> loadMask = Vector128.Create(ulong.MaxValue, ushort.MaxValue).AsByte();
		Vector128<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref source.GetReference()), loadMask, Vector128<byte>.Zero);
		Vector128<byte> packIndices = Vector128.Create((byte)4, 3, 2, 1, 0, 10, 10, 10, 9, 8, 7, 6, 5, 10, 10, 10);
		Vector128<byte> shiftControl = Vector128.Create(Avx512EncodeShiftControl).AsByte();
		return EncodeVbmiVl128(input, packIndices, shiftControl, symbolMask, alphabet.GetLower(), alphabet.GetUpper());
	}

	private static int EncodeUtf8Avx512VbmiVl128CustomSingle(ReadOnlySpan<byte> source, Span<byte> destination, byte[] alphabetBytes)
	{
		EncodeAvx512VbmiVl128CustomSingle(source, alphabetBytes).StoreUnsafe(ref destination.GetReference());
		return 10;
	}

	private static int EncodeCharsAvx512VbmiVl128CustomSingle(ReadOnlySpan<byte> source, Span<char> destination, byte[] alphabetBytes)
	{
		StoreEncodedChars(EncodeAvx512VbmiVl128CustomSingle(source, alphabetBytes), ref destination.GetReference());
		return 10;
	}

	private static unsafe int EncodeUtf8Avx512VbmiVl128Single(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		Vector128<byte> symbolMask = Vector128.Create((byte)SymbolMask);
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		Vector128<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref source.GetReference()), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
		EncodeVbmiVl128(input, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabet.GetLower(), alphabet.GetUpper()).StoreUnsafe(ref destination.GetReference());
		return 10;
	}

	private static unsafe int EncodeUtf8Avx512VbmiVl128(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		Vector128<byte> symbolMask = Vector128.Create(GetVectorSymbolMask(alphabetKind));
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		Vector128<byte> alphabetLow = alphabet.GetLower();
		Vector128<byte> alphabetHigh = alphabet.GetUpper();
		int blockCount = Math.Min(source.Length / 10, destination.Length / 16);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			Vector128<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 10)), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			EncodeVbmiVl128(firstInput, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationPointer);
			EncodeVbmiVl128(secondInput, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh).StoreUnsafe(ref Unsafe.Add(ref destinationPointer, 16));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector128<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			EncodeVbmiVl128(input, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh).StoreUnsafe(ref destinationPointer);
		}

		return blockCount * 10;
	}

	private static unsafe int EncodeCharsAvx512VbmiVl128Single(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		Vector128<byte> symbolMask = Vector128.Create((byte)SymbolMask);
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		Vector128<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref source.GetReference()), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
		Vector128<byte> encoded = EncodeVbmiVl128(input, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabet.GetLower(), alphabet.GetUpper());
		StoreEncodedChars(encoded, ref destination.GetReference());
		return 10;
	}

	private static unsafe int EncodeCharsAvx512VbmiVl128(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		Vector128<byte> symbolMask = Vector128.Create(GetVectorSymbolMask(alphabetKind));
		Vector256<byte> alphabet = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexAlphabetVector : Avx512VlRfcAlphabetVector;
		Vector128<byte> alphabetLow = alphabet.GetLower();
		Vector128<byte> alphabetHigh = alphabet.GetUpper();
		int blockCount = Math.Min(source.Length / 10, destination.Length / 16);
		ref byte sourcePointer = ref source.GetReference();
		ref char destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector128<byte> firstInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			Vector128<byte> secondInput = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref Unsafe.Add(ref sourcePointer, 10)), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			StoreEncodedChars(EncodeVbmiVl128(firstInput, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh), ref destinationPointer);
			StoreEncodedChars(EncodeVbmiVl128(secondInput, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh), ref Unsafe.Add(ref destinationPointer, 16));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 20);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 32);
		}

		if ((blockCount & 1) is not 0)
		{
			Vector128<byte> input = Avx512BW.VL.MaskLoad((byte*)Unsafe.AsPointer(ref sourcePointer), Avx512Vl128EncodeLoadMask, Vector128<byte>.Zero);
			StoreEncodedChars(EncodeVbmiVl128(input, Avx512Vl128PackIndicesVector, Avx512Vl128ShiftControlVector, symbolMask, alphabetLow, alphabetHigh), ref destinationPointer);
		}

		return blockCount * 10;
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

	private static int DecodeUtf8Avx512VbmiVl256(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		Vector256<byte> low = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeLowVector : Avx512VlRfcDecodeLowVector;
		Vector256<byte> high = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeHighVector : Avx512VlRfcDecodeHighVector;
		int blockCount = Math.Min(fullLength / 32, destination.Length / 20);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector256<byte> firstInput = Vector256.LoadUnsafe(ref sourcePointer);
			Vector256<byte> secondInput = Vector256.LoadUnsafe(ref sourcePointer, 32);
			Vector256<byte> first = Avx512Vbmi.VL.PermuteVar32x8x2(low, firstInput, high);
			Vector256<byte> second = Avx512Vbmi.VL.PermuteVar32x8x2(low, secondInput, high);

			if ((firstInput | first | secondInput | second).ExtractMostSignificantBits() is not 0)
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
			Vector256<byte> input = Vector256.LoadUnsafe(ref sourcePointer);
			Vector256<byte> values = Avx512Vbmi.VL.PermuteVar32x8x2(low, input, high);

			if ((input | values).ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}

	private static int DecodeCharsAvx512VbmiVl256(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		Vector256<byte> low = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeLowVector : Avx512VlRfcDecodeLowVector;
		Vector256<byte> high = alphabetKind is Rfc4648HexAlphabetKind ? Avx512VlHexDecodeHighVector : Avx512VlRfcDecodeHighVector;
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

			Vector256<byte> first = Avx512Vbmi.VL.PermuteVar32x8x2(low, firstInput, high);
			Vector256<byte> second = Avx512Vbmi.VL.PermuteVar32x8x2(low, secondInput, high);

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

		if
		(
			processedBlocks == pairCount * 2
			&& (blockCount & 1) is not 0
			&& TryNarrowAscii(ref sourcePointer, out Vector256<byte> input)
		)
		{
			Vector256<byte> values = Avx512Vbmi.VL.PermuteVar32x8x2(low, input, high);

			if (values.ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 32;
	}


	private static int DecodeUtf8Avx512(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector512<byte> deltaCheck = Vector512.Create(deltaCheck128);
		Vector512<byte> deltaRebase = Vector512.Create(deltaRebase128);
		Vector512<byte> nibbleMask = Vector512.Create((byte)0x0f);
		Vector512<sbyte> lowerBound = Vector512.Create((sbyte)mapLowerBound);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> first = DecodeEight(Vector512.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> firstInvalidMask);
			Vector512<byte> second = DecodeEight(Vector512.LoadUnsafe(ref sourcePointer, 64), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> secondInvalidMask);

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
			Vector512<byte> values = DecodeEight(Vector512.LoadUnsafe(ref sourcePointer), deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> invalidMask);

			if (IsValidAvx512(invalidMask))
			{
				StoreDecoded(PackDecoded(values, packIndices), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 64;
	}

	private static int DecodeCharsAvx512(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetDecodeShuffleMap(alphabetKind, out Vector128<byte> deltaCheck128, out Vector128<byte> deltaRebase128, out byte mapLowerBound);
		Vector512<byte> deltaCheck = Vector512.Create(deltaCheck128);
		Vector512<byte> deltaRebase = Vector512.Create(deltaRebase128);
		Vector512<byte> nibbleMask = Vector512.Create((byte)0x0f);
		Vector512<sbyte> lowerBound = Vector512.Create((sbyte)mapLowerBound);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref char sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if
			(
				!TryNarrowAscii(ref sourcePointer, out Vector512<byte> firstInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 64), out Vector512<byte> secondInput)
			)
			{
				break;
			}

			Vector512<byte> first = DecodeEight(firstInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> firstInvalidMask);
			Vector512<byte> second = DecodeEight(secondInput, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> secondInvalidMask);

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

		if
		(
			processedBlocks == pairCount * 2
			&& (blockCount & 1) is not 0
			&& TryNarrowAscii(ref sourcePointer, out Vector512<byte> input)
		)
		{
			Vector512<byte> values = DecodeEight(input, deltaCheck, deltaRebase, nibbleMask, lowerBound, out Vector512<byte> invalidMask);

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

	private int DecodeUtf8Avx512Vbmi(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetAvx512DecodeTables(alphabetKind, out Vector512<byte> low, out Vector512<byte> high);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref byte sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			Vector512<byte> firstInput = Vector512.LoadUnsafe(ref sourcePointer);
			Vector512<byte> secondInput = Vector512.LoadUnsafe(ref sourcePointer, 64);
			Vector512<byte> first = Avx512Vbmi.PermuteVar64x8x2(low, firstInput, high);
			Vector512<byte> second = Avx512Vbmi.PermuteVar64x8x2(low, secondInput, high);

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
			Vector512<byte> input = Vector512.LoadUnsafe(ref sourcePointer);
			Vector512<byte> values = Avx512Vbmi.PermuteVar64x8x2(low, input, high);

			if ((input | values).ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values, packIndices), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 64;
	}

	private int DecodeCharsAvx512Vbmi(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		GetAvx512DecodeTables(alphabetKind, out Vector512<byte> low, out Vector512<byte> high);
		Vector512<byte> packIndices = Avx512DecodedPackIndicesVector;
		int blockCount = Math.Min(fullLength / 64, destination.Length / 40);
		ref char sourcePointer = ref source.GetReference();
		ref byte destinationPointer = ref destination.GetReference();
		int pairCount = blockCount >> 1;
		int processedBlocks = 0;

		for (int i = 0; i < pairCount; ++i)
		{
			if
			(
				!TryNarrowAscii(ref sourcePointer, out Vector512<byte> firstInput)
				|| !TryNarrowAscii(ref Unsafe.Add(ref sourcePointer, 64), out Vector512<byte> secondInput)
			)
			{
				break;
			}

			Vector512<byte> first = Avx512Vbmi.PermuteVar64x8x2(low, firstInput, high);
			Vector512<byte> second = Avx512Vbmi.PermuteVar64x8x2(low, secondInput, high);

			if ((first | second).ExtractMostSignificantBits() is not 0)
			{
				break;
			}

			StoreDecodedOverlapping(PackDecoded(first, packIndices), ref destinationPointer);
			StoreDecoded(PackDecoded(second, packIndices), ref Unsafe.Add(ref destinationPointer, 40));
			sourcePointer = ref Unsafe.Add(ref sourcePointer, 128);
			destinationPointer = ref Unsafe.Add(ref destinationPointer, 80);
			processedBlocks += 2;
		}

		if
		(
			processedBlocks == pairCount * 2
			&& (blockCount & 1) is not 0
			&& TryNarrowAscii(ref sourcePointer, out Vector512<byte> input)
		)
		{
			Vector512<byte> values = Avx512Vbmi.PermuteVar64x8x2(low, input, high);

			if (values.ExtractMostSignificantBits() is 0)
			{
				StoreDecoded(PackDecoded(values, packIndices), ref destinationPointer);
				++processedBlocks;
			}
		}

		return processedBlocks * 64;
	}
}
