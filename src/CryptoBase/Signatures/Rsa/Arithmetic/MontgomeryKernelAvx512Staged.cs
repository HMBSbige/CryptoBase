namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAvx512 for the windows that the registers do not hold with the operands: the JIT would spill vectors to a stack aligned for a quarter of one, and every spill would cross a cache line where the stack happened to lie so. The digits of the left operand and of the modulus go as doubles into staging, which starts on a 64-byte boundary, and each iteration reads them there; only the accumulator stays in registers.
internal readonly unsafe struct MontgomeryKernelAvx512Staged<TWindow> : IMontgomeryKernel where TWindow : struct, IAvx512StagedWindow<TWindow>
{
	private const int R = 52;
	private const int S = 64 - R;

	// The lanes that the scalar side keeps, and the rows of scratch: b as doubles, then the parts of those lanes and the next that come from b.
	private const int ScalarLanes = 4;
	private const int Rows = ScalarLanes + 2;

	// The bits of 2^104 and of 2^52; the lane shifted in at iteration i carries LowOffset + i·Offset, the offset of every lane after the low parts of that iteration.
	private const ulong HighBits = 0x4670000000000000UL;
	private const ulong LowBits = 0x4330000000000000UL;
	private const ulong LowOffset = 2 * LowBits;
	private const ulong Offset = unchecked(2 * LowBits + 2 * HighBits);

	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512DQ.IsSupported && Bmi2.X64.IsSupported;

	public static int DigitBits => R;

	// A lane gains less than 2^54 per iteration, so the sums stay below 2^64 far beyond the digits that a window holds; the masks of Normalize hold 192 lanes.
	public static int MaxDigitCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Math.Min(8 * TWindow.Count, 64 * MaskWords.Length);
	}

	// Rows of MaxDigitCount words, so that they lie at fixed offsets, then two vectors of staging for each of the window and the room to align them.
	public static int GetScratchLength(int digitCount)
	{
		return Rows * MaxDigitCount + 16 * TWindow.Count + 8;
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		modulus.CopyTo(prepared);
	}

	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		Multiply(result, value, value, modulus, negativeInverse, scratch);
	}

	// Kept out of its callers and optimized from the first call, with the spans pinned for the masked loads and stores, as in MontgomeryKernelAvx512.Multiply.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int count = modulus.Length;
		int row = MaxDigitCount;

		Debug.Assert(count <= row && result.Length == count && left.Length == count && right.Length == count && scratch.Length >= Rows * row);

		// ReSharper disable UnusedVariable
		fixed (ulong* resultPointer = &MemoryMarshal.GetReference(result))
		fixed (ulong* leftPointer = &MemoryMarshal.GetReference(left))
		fixed (ulong* rightPointer = &MemoryMarshal.GetReference(right))
		fixed (ulong* modulusPointer = &MemoryMarshal.GetReference(modulus))
		fixed (ulong* scratchPointer = &MemoryMarshal.GetReference(scratch))
		// ReSharper restore UnusedVariable
		{
			ref ulong x = ref MemoryMarshal.GetReference(left);
			ref ulong n = ref MemoryMarshal.GetReference(modulus);
			ref ulong rows = ref MemoryMarshal.GetReference(scratch);
			ref double staging = ref Stage(ref x, ref n, count, ref Unsafe.Add(ref rows, Rows * row));
			Vector512<double> high = Vector512.Create(BitConverter.UInt64BitsToDouble(HighBits));
			Vector512<double> low = Vector512.Create(BitConverter.UInt64BitsToDouble(HighBits + 1));
			Products(ref x, ref MemoryMarshal.GetReference(right), count, ref rows, high, low);

			TWindow acc = default;
			Vector512<ulong> next = Vector512.Create(LowOffset);
			Vector512<ulong> step = Vector512.Create(Offset);
			ulong n0 = n;
			ulong n1 = Digit(ref n, count, 1);
			ulong n2 = Digit(ref n, count, 2);
			ulong n3 = Digit(ref n, count, 3);
			// u·(−n⁻¹·2^12) mod 2^64 is m·2^12.
			ulong inverse = negativeInverse << S;
			ulong s0 = 0;
			ulong s1 = 0;
			ulong s2 = 0;
			ulong s3 = 0;

			for (nint i = 0; i < count; ++i)
			{
				ulong u = s0 + Unsafe.Add(ref rows, row + i);
				ulong m = u * inverse;
				TWindow.Accumulate(ref acc, ref staging, 0, Vector512.Create(Unsafe.As<ulong, double>(ref Unsafe.Add(ref rows, i))), Avx512DQ.ConvertToVector512Double(Vector512.Create(m >> S)), high, low);
				// The lanes before the shift carry the offset that the lane shifted in starts with.
				ulong lane4 = (TWindow.First(in acc) - next).GetElement(ScalarLanes);
				TWindow.Shift(ref acc, next);
				next += step;
				// The parts from b first, so that each product with m is used as soon as it is taken.
				ulong t0 = s1 + Unsafe.Add(ref rows, 2 * row + i);
				ulong t1 = s2 + Unsafe.Add(ref rows, 3 * row + i);
				ulong t2 = s3 + Unsafe.Add(ref rows, 4 * row + i);
				ulong t3 = lane4 + Unsafe.Add(ref rows, 5 * row + i);
				s3 = t3 + Bmi2.X64.MultiplyNoFlags(m, n3);
				s2 = t2 + Bmi2.X64.MultiplyNoFlags(m, n2) + (m * n3 >> S);
				s1 = t1 + Bmi2.X64.MultiplyNoFlags(m, n1) + (m * n2 >> S);
				s0 = t0 + Bmi2.X64.MultiplyNoFlags(m, n0) + (m * n1 >> S) + (u + (m * n0 >> S) >> R);
			}

			Vector512<ulong> shared = next - Vector512.Create(LowOffset);
			TWindow.ReplaceLow(ref acc, Vector512.Create(s0, s1, s2, s3, 0, 0, 0, 0) + shared, Vector512.Create(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0));
			TWindow.Pass(ref acc, shared, Vector512<ulong>.Zero);
			Normalize(ref acc, ref MemoryMarshal.GetReference(result), count);
		}
	}

	// The digits of x and of the modulus as doubles, a vector of each in turn, from the first 64-byte boundary at or after start, which it returns. If the scratch moves meanwhile, only the speed changes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref double Stage(ref ulong x, ref ulong n, int count, ref ulong start)
	{
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		ref double staging = ref Unsafe.As<ulong, double>(ref Unsafe.AddByteOffset(ref start, (address + 63 & ~(nuint)63) - address));

		for (int v = 0; v < TWindow.Count; ++v)
		{
			Vector512<ulong> lanes = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Clamp(count - 8 * v, 0, 8)));
			Avx512DQ.ConvertToVector512Double(Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref x, 8 * v)), lanes, Vector512<ulong>.Zero)).StoreUnsafe(ref staging, (nuint)(16 * v));
			Avx512DQ.ConvertToVector512Double(Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref n, 8 * v)), lanes, Vector512<ulong>.Zero)).StoreUnsafe(ref staging, (nuint)(16 * v + 8));
		}

		return ref staging;
	}

	// Row 0: each digit b_i of the right operand as a double. Rows 1 to 5: the parts of its products with the first four digits of the left one that lanes 0 to 4 gain at iteration i: lo(a0·b_i), then hi(a_{j−1}·b_i) + lo(a_j·b_i), then hi(a3·b_i). Eight digits at a time.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Products(ref ulong x, ref ulong y, int count, ref ulong rows, Vector512<double> high, Vector512<double> low)
	{
		int row = MaxDigitCount;
		Vector512<double> a0 = Vector512.Create((double)x);
		Vector512<double> a1 = Vector512.Create((double)Digit(ref x, count, 1));
		Vector512<double> a2 = Vector512.Create((double)Digit(ref x, count, 2));
		Vector512<double> a3 = Vector512.Create((double)Digit(ref x, count, 3));
		Vector512<ulong> highBits = Vector512.Create(HighBits);
		Vector512<ulong> lowBits = Vector512.Create(LowBits);

		for (int j = 0; j < count; j += 8)
		{
			Vector512<ulong> lanes = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Min(count - j, 8)));
			Vector512<double> b = Avx512DQ.ConvertToVector512Double(Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref y, j)), lanes, Vector512<ulong>.Zero));
			Vector512<double> t0 = Avx512F.FusedMultiplyAdd(a0, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a1, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t2 = Avx512F.FusedMultiplyAdd(a2, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t3 = Avx512F.FusedMultiplyAdd(a3, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<ulong> l0 = Avx512F.FusedMultiplyAdd(a0, b, low - t0).AsUInt64() - lowBits;
			Vector512<ulong> l1 = Avx512F.FusedMultiplyAdd(a1, b, low - t1).AsUInt64() - lowBits;
			Vector512<ulong> l2 = Avx512F.FusedMultiplyAdd(a2, b, low - t2).AsUInt64() - lowBits;
			Vector512<ulong> l3 = Avx512F.FusedMultiplyAdd(a3, b, low - t3).AsUInt64() - lowBits;
			Store(b.AsUInt64(), ref rows, j, lanes);
			Store(l0, ref rows, row + j, lanes);
			Store(t0.AsUInt64() - highBits + l1, ref rows, 2 * row + j, lanes);
			Store(t1.AsUInt64() - highBits + l2, ref rows, 3 * row + j, lanes);
			Store(t2.AsUInt64() - highBits + l3, ref rows, 4 * row + j, lanes);
			Store(t3.AsUInt64() - highBits, ref rows, 5 * row + j, lanes);
		}
	}

	// Digit index of a value of count digits, zero past them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Digit(ref ulong digits, int count, int index)
	{
		return index < count ? Unsafe.Add(ref digits, index) : 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(Vector512<ulong> value, ref ulong output, int index, Vector512<ulong> lanes)
	{
		Avx512F.MaskStore((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref output, index)), lanes, value);
	}

	// The ripple of carries, a word of 64 lanes at a time, then the stores.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Normalize(ref TWindow acc, ref ulong result, int count)
	{
		int words = (count + 63) / 64;
		MaskWords generateWords = default;
		MaskWords propagateWords = default;
		Span<ulong> generate = generateWords;
		Span<ulong> propagate = propagateWords;
		TWindow.Masks(in acc, 0, generate, propagate);
		ulong carry = 0;

		for (int w = 0; w < words; ++w)
		{
			ulong shifted = generate[w] << 1 | carry;
			ulong sum = shifted + propagate[w];
			carry = generate[w] >> 63 | (shifted & propagate[w] | (shifted | propagate[w]) & ~sum) >> 63;
			generate[w] = sum ^ propagate[w];
		}

		TWindow.Store(in acc, 0, generate, ref result, count);
	}

	[InlineArray(3)]
	private struct MaskWords
	{
		public const int Length = 3;

		private ulong _element;
	}
}
