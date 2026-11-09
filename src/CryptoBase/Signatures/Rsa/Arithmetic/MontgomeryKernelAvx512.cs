namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Digits of 52 bits with FP64 FMA on AVX-512, after Emmart, Zheng and Weems, "Faster Modular Exponentiation Using Double Precision Floating Point Arithmetic on the GPU" (IEEE ARITH 2018). A digit is exact as a double, and a product a·b < 2^104 splits into two digits with two FMAs rounded toward −∞:
//   t = fma(a, b, 2^104) = 2^104 + h with h = ⌊a·b/2^52⌋·2^52, whose bits less those of 2^104 are the high digit h/2^52;
//   fma(a, b, (2^104 + 2^52) − t) = a·b − h + 2^52, in [2^52, 2^53), whose bits less those of 2^52 are the low digit a·b mod 2^52.
// Both stay integers in the bits of a double, so that the sums run on 64-bit integer lanes without conversions.
// The multiplication scans the right operand digit by digit as in MontgomeryKernel64, with the window of the sum in a window of vectors (see IAvx512Window): at iteration i lane j holds digit i + j, gains the low parts of a·b_i and n·m_i, shifts down by one lane and gains the high parts. Every lane thus gains the bits of 2^52 and 2^104 twice per iteration; the lane shifted in at the top carries the offset of the others, so that all lanes share one offset, removed at the end.
// m_i = (digit i of the sum)·(−n⁻¹) mod 2^52 must not wait for the vectors: the scalar side keeps lanes 0 to 3 exactly and takes lane 4 after the low parts from the vector, which four iterations of the scalar side separate from its use in m. The parts of those lanes that come from b_i are taken for every i before the loop, with the vectors (see Avx512Window.Products); the products of m_i with the first digits of n take m_i·2^12 as their second operand, so that the high word of a 64 × 64-bit product is the high digit and the low word shifted right by 12 bits the low digit.
// At the end one carry pass leaves every lane below 2^52 + 2^9, so that a lane at or above 2^52 carries exactly 1 and one equal to 2^52 − 1 passes on what it receives: the carries then ripple as in an addition of masks of those lanes.
internal readonly unsafe struct MontgomeryKernelAvx512<TWindow> : IMontgomeryKernel where TWindow : struct, IAvx512Window<TWindow>
{
	private const int R = 52;
	private const int S = 64 - R;

	// The lanes that the scalar side keeps, and the rows of scratch: b as doubles, then the parts of those lanes and the next that come from b.
	private const int ScalarLanes = 4;
	private const int Rows = ScalarLanes + 2;

	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512DQ.IsSupported && Bmi2.X64.IsSupported;

	public static int DigitBits => R;

	// A lane gains less than 2^54 per iteration, so the sums stay below 2^64 far beyond the digits that a window holds; the masks of Normalize hold 192 lanes.
	public static int MaxDigitCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Math.Min(8 * TWindow.Count, 64 * Avx512Window.MaskWords.Length);
	}

	// Rows of MaxDigitCount words, so that they lie at fixed offsets.
	public static int GetScratchLength(int digitCount)
	{
		return Rows * MaxDigitCount;
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		modulus.CopyTo(prepared);
	}

	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		Multiply(result, value, value, modulus, negativeInverse, scratch);
	}

	// Kept out of its callers, where the window methods would no longer inline and the window would leave the registers, and optimized from the first call. The masked loads and stores take pointers into the spans, which stay pinned until it returns; the rest reaches them through the spans, as refs from the pointers would change how the loop takes its registers.
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
			Unsafe.SkipInit(out TWindow a);
			Unsafe.SkipInit(out TWindow nn);
			TWindow.Load(ref a, ref x, count, 0);
			TWindow.Load(ref nn, ref n, count, 0);
			Vector512<double> high = Vector512.Create(BitConverter.UInt64BitsToDouble(Avx512Window.HighBits));
			Vector512<double> low = Vector512.Create(BitConverter.UInt64BitsToDouble(Avx512Window.HighBits + 1));
			Avx512Window.Products(ref x, ref MemoryMarshal.GetReference(right), count, ref rows, row, high, low);

			TWindow acc = default;
			Vector512<ulong> next = Vector512.Create(Avx512Window.LowOffset);
			Vector512<ulong> step = Vector512.Create(Avx512Window.Offset);
			ulong n0 = n;
			ulong n1 = Avx512Window.Digit(ref n, count, 1);
			ulong n2 = Avx512Window.Digit(ref n, count, 2);
			ulong n3 = Avx512Window.Digit(ref n, count, 3);
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
				TWindow.Accumulate(ref acc, in a, in nn, Vector512.Create(Unsafe.As<ulong, double>(ref Unsafe.Add(ref rows, i))), Avx512DQ.ConvertToVector512Double(Vector512.Create(m >> S)), high, low);
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

			Vector512<ulong> shared = next - Vector512.Create(Avx512Window.LowOffset);
			TWindow.ReplaceLow(ref acc, Vector512.Create(s0, s1, s2, s3, 0, 0, 0, 0) + shared, Vector512.Create(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0));
			TWindow.Pass(ref acc, shared, Vector512<ulong>.Zero);
			Avx512Window.Normalize(ref acc, ref MemoryMarshal.GetReference(result), count);
		}
	}
}
