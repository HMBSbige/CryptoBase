namespace CryptoBase.Hashes.Crc32;

internal static partial class Crc32Vectorized
{
	private const int Avx2EightStreamThresholdInBytes = 4 * 1024;

	internal static readonly Crc32X86FoldingConstants IeeeX86Constants = new(0x011542778aUL, 0x01322d1430UL, 0x01e88ef372UL, 0x014a7fe880UL, 0x0154442bd4UL, 0x01c6e41596UL, 0x00f1da05aaUL, 0x015a546366UL, 0x01751997d0UL, 0x00ccaa009eUL);

	internal static readonly Crc32X86FoldingConstants CastagnoliX86Constants = new(0x00dcb17aa4UL, 0x00b9e02b86UL, 0x006992cea2UL, 0x0206e38d70UL, 0x00740eef02UL, 0x009e4addf8UL, 0x003da6d0cbUL, 0x00ba4fc28eUL, 0x0ec1068c50UL, 0x00493c7d27UL);

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static Vector128<ulong> FoldX86512(uint state, ReadOnlySpan<byte> source, in Crc32X86FoldingConstants constants, out int bytesConsumed)
	{
		Debug.Assert(Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported);
		Debug.Assert(source.Length >= 4 * Vector512<byte>.Count);

		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;
		Vector512<ulong> x1 = Vector512.LoadUnsafe(ref sourceRef).AsUInt64() ^ Vector512.CreateScalar((ulong)state);
		Vector512<ulong> x2 = Vector512.LoadUnsafe(ref sourceRef, 64).AsUInt64();
		Vector512<ulong> x3 = Vector512.LoadUnsafe(ref sourceRef, 128).AsUInt64();
		Vector512<ulong> x4 = Vector512.LoadUnsafe(ref sourceRef, 192).AsUInt64();
		sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector512<byte>.Count);
		length -= 4 * Vector512<byte>.Count;

		Vector512<ulong> fold2048 = constants.Fold2048Vector512;

		while (length >= 4 * Vector512<byte>.Count)
		{
			x1 = Fold512(Vector512.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold2048);
			x2 = Fold512(Vector512.LoadUnsafe(ref sourceRef, 64).AsUInt64(), x2, fold2048);
			x3 = Fold512(Vector512.LoadUnsafe(ref sourceRef, 128).AsUInt64(), x3, fold2048);
			x4 = Fold512(Vector512.LoadUnsafe(ref sourceRef, 192).AsUInt64(), x4, fold2048);
			sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector512<byte>.Count);
			length -= 4 * Vector512<byte>.Count;
		}

		Vector512<ulong> fold1024 = constants.Fold1024Vector512;
		x1 = Fold512(x3, x1, fold1024);
		x2 = Fold512(x4, x2, fold1024);

		if (length >= 2 * Vector512<byte>.Count)
		{
			x1 = Fold512(Vector512.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold1024);
			x2 = Fold512(Vector512.LoadUnsafe(ref sourceRef, 64).AsUInt64(), x2, fold1024);
			sourceRef = ref Unsafe.Add(ref sourceRef, 2 * Vector512<byte>.Count);
			length -= 2 * Vector512<byte>.Count;
		}

		Vector512<ulong> fold512 = constants.Fold512Vector512;
		x1 = Fold512(x2, x1, fold512);

		if (length >= Vector512<byte>.Count)
		{
			x1 = Fold512(Vector512.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold512);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector512<byte>.Count);
			length -= Vector512<byte>.Count;
		}

		Vector256<ulong> fold256 = constants.Fold256Vector256;
		Vector256<ulong> folded256 = Fold256(x1.GetUpper(), x1.GetLower(), fold256);

		if (length >= Vector256<byte>.Count)
		{
			folded256 = Fold256(Vector256.LoadUnsafe(ref sourceRef).AsUInt64(), folded256, fold256);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector256<byte>.Count);
			length -= Vector256<byte>.Count;
		}

		Vector128<ulong> fold128 = constants.Fold128Vector128;
		Vector128<ulong> folded = Fold128(folded256.GetUpper(), folded256.GetLower(), fold128);

		if (length >= Vector128<byte>.Count)
		{
			folded = Fold128(Load(ref sourceRef, 0), folded, fold128);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		folded = FoldRemainingX86(folded, ref sourceRef, ref length, in constants);
		bytesConsumed = source.Length - length;
		return folded;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static Vector128<ulong> FoldX86256(uint state, ReadOnlySpan<byte> source, in Crc32X86FoldingConstants constants, out int bytesConsumed)
	{
		Debug.Assert(Avx2.IsSupported && Pclmulqdq.V256.IsSupported);
		Debug.Assert(source.Length >= 4 * Vector256<byte>.Count);

		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;
		Vector256<ulong> x1;
		Vector256<ulong> x2;
		Vector256<ulong> x3;
		Vector256<ulong> x4;

		if (length >= Avx2EightStreamThresholdInBytes)
		{
			x1 = Vector256.LoadUnsafe(ref sourceRef).AsUInt64() ^ Vector256.CreateScalar((ulong)state);
			x2 = Vector256.LoadUnsafe(ref sourceRef, 32).AsUInt64();
			x3 = Vector256.LoadUnsafe(ref sourceRef, 64).AsUInt64();
			x4 = Vector256.LoadUnsafe(ref sourceRef, 96).AsUInt64();
			Vector256<ulong> x5 = Vector256.LoadUnsafe(ref sourceRef, 128).AsUInt64();
			Vector256<ulong> x6 = Vector256.LoadUnsafe(ref sourceRef, 160).AsUInt64();
			Vector256<ulong> x7 = Vector256.LoadUnsafe(ref sourceRef, 192).AsUInt64();
			Vector256<ulong> x8 = Vector256.LoadUnsafe(ref sourceRef, 224).AsUInt64();
			sourceRef = ref Unsafe.Add(ref sourceRef, 8 * Vector256<byte>.Count);
			length -= 8 * Vector256<byte>.Count;

			Vector256<ulong> fold2048 = constants.Fold2048Vector256;

			while (length >= 8 * Vector256<byte>.Count)
			{
				x1 = Fold256(Vector256.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold2048);
				x2 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 32).AsUInt64(), x2, fold2048);
				x3 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 64).AsUInt64(), x3, fold2048);
				x4 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 96).AsUInt64(), x4, fold2048);
				x5 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 128).AsUInt64(), x5, fold2048);
				x6 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 160).AsUInt64(), x6, fold2048);
				x7 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 192).AsUInt64(), x7, fold2048);
				x8 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 224).AsUInt64(), x8, fold2048);
				sourceRef = ref Unsafe.Add(ref sourceRef, 8 * Vector256<byte>.Count);
				length -= 8 * Vector256<byte>.Count;
			}

			Vector256<ulong> fold1024 = constants.Fold1024Vector256;
			x1 = Fold256(x5, x1, fold1024);
			x2 = Fold256(x6, x2, fold1024);
			x3 = Fold256(x7, x3, fold1024);
			x4 = Fold256(x8, x4, fold1024);
		}
		else
		{
			x1 = Vector256.LoadUnsafe(ref sourceRef).AsUInt64() ^ Vector256.CreateScalar((ulong)state);
			x2 = Vector256.LoadUnsafe(ref sourceRef, 32).AsUInt64();
			x3 = Vector256.LoadUnsafe(ref sourceRef, 64).AsUInt64();
			x4 = Vector256.LoadUnsafe(ref sourceRef, 96).AsUInt64();
			sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector256<byte>.Count);
			length -= 4 * Vector256<byte>.Count;

			Vector256<ulong> fold1024 = constants.Fold1024Vector256;

			while (length >= 4 * Vector256<byte>.Count)
			{
				x1 = Fold256(Vector256.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold1024);
				x2 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 32).AsUInt64(), x2, fold1024);
				x3 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 64).AsUInt64(), x3, fold1024);
				x4 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 96).AsUInt64(), x4, fold1024);
				sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector256<byte>.Count);
				length -= 4 * Vector256<byte>.Count;
			}
		}

		Vector256<ulong> fold512 = constants.Fold512Vector256;
		x1 = Fold256(x3, x1, fold512);
		x2 = Fold256(x4, x2, fold512);

		if (length >= 2 * Vector256<byte>.Count)
		{
			x1 = Fold256(Vector256.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold512);
			x2 = Fold256(Vector256.LoadUnsafe(ref sourceRef, 32).AsUInt64(), x2, fold512);
			sourceRef = ref Unsafe.Add(ref sourceRef, 2 * Vector256<byte>.Count);
			length -= 2 * Vector256<byte>.Count;
		}

		Vector256<ulong> fold256 = constants.Fold256Vector256;
		x1 = Fold256(x2, x1, fold256);

		if (length >= Vector256<byte>.Count)
		{
			x1 = Fold256(Vector256.LoadUnsafe(ref sourceRef).AsUInt64(), x1, fold256);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector256<byte>.Count);
			length -= Vector256<byte>.Count;
		}

		Vector128<ulong> fold128 = constants.Fold128Vector128;
		Vector128<ulong> folded = Fold128(x1.GetUpper(), x1.GetLower(), fold128);

		if (length >= Vector128<byte>.Count)
		{
			folded = Fold128(Load(ref sourceRef, 0), folded, fold128);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		folded = FoldRemainingX86(folded, ref sourceRef, ref length, in constants);
		bytesConsumed = source.Length - length;
		return folded;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static Vector128<ulong> FoldX86128(uint state, ReadOnlySpan<byte> source, in Crc32X86FoldingConstants constants, out int bytesConsumed)
	{
		Debug.Assert(Pclmulqdq.IsSupported);
		Debug.Assert(source.Length >= Vector128<byte>.Count);

		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;
		Vector128<ulong> fold512 = constants.Fold512Vector128;
		Vector128<ulong> fold128 = constants.Fold128Vector128;
		Vector128<ulong> x1;

		if (length >= 8 * Vector128<byte>.Count)
		{
			x1 = Load(ref sourceRef, 0) ^ Vector128.CreateScalar((ulong)state);
			Vector128<ulong> x2 = Load(ref sourceRef, 16);
			Vector128<ulong> x3 = Load(ref sourceRef, 32);
			Vector128<ulong> x4 = Load(ref sourceRef, 48);
			sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector128<byte>.Count);
			length -= 4 * Vector128<byte>.Count;

			do
			{
				x1 = Fold128(Load(ref sourceRef, 0), x1, fold512);
				x2 = Fold128(Load(ref sourceRef, 16), x2, fold512);
				x3 = Fold128(Load(ref sourceRef, 32), x3, fold512);
				x4 = Fold128(Load(ref sourceRef, 48), x4, fold512);
				sourceRef = ref Unsafe.Add(ref sourceRef, 4 * Vector128<byte>.Count);
				length -= 4 * Vector128<byte>.Count;
			} while (length >= 4 * Vector128<byte>.Count);

			x1 = Fold128(x2, x1, fold128);
			x1 = Fold128(x3, x1, fold128);
			x1 = Fold128(x4, x1, fold128);
		}
		else
		{
			x1 = Load(ref sourceRef, 0) ^ Vector128.CreateScalar((ulong)state);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		x1 = FoldRemainingX86(x1, ref sourceRef, ref length, in constants);
		bytesConsumed = source.Length - length;
		return x1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint ReduceIeeeX86(Vector128<ulong> value)
	{
		Vector128<ulong> bitmask = Vector128.Create((ulong)uint.MaxValue);
		value = Sse2.ShiftRightLogical128BitLane(value, 8) ^ Pclmulqdq.CarrylessMultiply(value, Vector128.CreateScalar(0x00ccaa009eUL), 0x00);
		value = Pclmulqdq.CarrylessMultiply(value & bitmask, Vector128.CreateScalar(0x0163cd6124UL), 0x00) ^ Sse2.ShiftRightLogical128BitLane(value, 4);

		Vector128<ulong> polynomialMu = Vector128.Create(0x01db710641UL, 0x01f7011641UL);
		Vector128<ulong> reduction = Pclmulqdq.CarrylessMultiply(value & bitmask, polynomialMu, 0x10) & bitmask;
		reduction = Pclmulqdq.CarrylessMultiply(reduction, polynomialMu, 0x00);
		return (value ^ reduction).AsUInt32().GetElement(1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint ReduceCastagnoliX86(Vector128<ulong> value)
	{
		Debug.Assert(Sse42.X64.IsSupported);
		ulong state = Sse42.X64.Crc32(0, value.GetElement(0));
		return (uint)Sse42.X64.Crc32(state, value.GetElement(1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint ReduceCastagnoliBarrettX86(Vector128<ulong> value)
	{
		Vector128<ulong> bitmask = Vector128.Create((ulong)uint.MaxValue);
		value = Sse2.ShiftRightLogical128BitLane(value, 8)
				^ Pclmulqdq.CarrylessMultiply(value, Vector128.CreateScalar(0x014cd00bd6UL), 0x00);
		value = Pclmulqdq.CarrylessMultiply(value & bitmask, Vector128.CreateScalar(0x00dd45aab8UL), 0x00)
				^ Sse2.ShiftRightLogical128BitLane(value, 4);

		Vector128<ulong> polynomialMu = Vector128.Create(0x0105ec76f1UL, 0x00dea713f1UL);
		Vector128<ulong> reduction = Pclmulqdq.CarrylessMultiply(value & bitmask, polynomialMu, 0x10) & bitmask;
		reduction = Pclmulqdq.CarrylessMultiply(reduction, polynomialMu, 0x00);
		return (value ^ reduction).AsUInt32().GetElement(1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Fold512(Vector512<ulong> target, Vector512<ulong> source, Vector512<ulong> constants)
	{
		return target ^ Pclmulqdq.V512.CarrylessMultiply(source, constants, 0x11) ^ Pclmulqdq.V512.CarrylessMultiply(source, constants, 0x00);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Fold256(Vector256<ulong> target, Vector256<ulong> source, Vector256<ulong> constants)
	{
		return Pclmulqdq.V256.CarrylessMultiply(source, constants, 0x11) ^ Pclmulqdq.V256.CarrylessMultiply(source, constants, 0x00) ^ target;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Fold128(Vector128<ulong> target, Vector128<ulong> source, Vector128<ulong> constants)
	{
		return target ^ Pclmulqdq.CarrylessMultiply(source, constants, 0x11) ^ Pclmulqdq.CarrylessMultiply(source, constants, 0x00);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> FoldRemainingX86(Vector128<ulong> state, ref byte source, ref int length, in Crc32X86FoldingConstants constants)
	{
		Vector128<ulong> fold128 = constants.Fold128Vector128;

		while (length >= Vector128<byte>.Count)
		{
			state = Fold128(Load(ref source, 0), state, fold128);
			source = ref Unsafe.Add(ref source, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		if (length > 0 && Ssse3.IsSupported)
		{
			state = FoldPartialX86(state, ref source, length, fold128);
			length = 0;
		}

		return state;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> FoldPartialX86(Vector128<ulong> state, ref byte source, int length, Vector128<ulong> fold128)
	{
		Debug.Assert(Ssse3.IsSupported);
		Debug.Assert((uint)(length - 1) < Vector128<byte>.Count - 1);

		Vector128<byte> sequence = Vector128.Create((byte)0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
		Vector128<byte> shiftLeft = sequence + Vector128.Create((byte)(length - Vector128<byte>.Count));
		Vector128<byte> shiftRight = shiftLeft ^ Vector128.Create((byte)0x80);
		Vector128<ulong> overflow = Vector128.ShuffleNative(state.AsByte(), shiftLeft).AsUInt64();
		Vector128<ulong> shiftedState = Vector128.ShuffleNative(state.AsByte(), shiftRight).AsUInt64();

		ref byte tailStart = ref Unsafe.Add(ref source, length - Vector128<byte>.Count);
		Vector128<byte> tail = Load(ref tailStart, 0).AsByte();
		Vector128<byte> tailMask = Vector128.GreaterThan(shiftLeft.AsSByte(), Vector128.Create((sbyte)-1)).AsByte();
		shiftedState ^= (tail & tailMask).AsUInt64();

		return Fold128(shiftedState, overflow, fold128);
	}
}
