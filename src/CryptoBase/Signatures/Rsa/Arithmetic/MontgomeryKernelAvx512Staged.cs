namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAvx512 for the windows that the registers do not hold with the operands: the JIT would spill vectors to a stack aligned for a quarter of one, and every spill would cross a cache line where the stack happened to lie so. The digits of the left operand and of the modulus go as doubles into staging, which starts on a 64-byte boundary, and each iteration reads them there; only the accumulator stays in registers.
internal readonly unsafe struct MontgomeryKernelAvx512Staged<TWindow> : IMontgomeryKernel where TWindow : struct, IAvx512StagedWindow<TWindow>
{
	private const int R = 52;
	private const int S = 64 - R;

	// The lanes that the scalar side keeps, and the rows of scratch: b as doubles, then the parts of those lanes and the next that come from b.
	private const int ScalarLanes = 4;
	private const int Rows = ScalarLanes + 2;

	public static bool IsSupported => MontgomeryKernelAvx512<Avx512Window>.IsSupported;

	public static int DigitBits => R;

	// A lane gains less than 2^54 per iteration, so the sums stay below 2^64 far beyond the digits that a window holds; the masks of Normalize hold 192 lanes.
	public static int MaxDigitCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Math.Min(8 * TWindow.Count, 64 * Avx512Window.MaskWords.Length);
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

			Vector512<ulong> shared = next - Vector512.Create(Avx512Window.LowOffset);
			TWindow.ReplaceLow(ref acc, Vector512.Create(s0, s1, s2, s3, 0, 0, 0, 0) + shared, Vector512.Create(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0));
			TWindow.Pass(ref acc, shared, Vector512<ulong>.Zero);
			Avx512Window.Normalize(ref acc, ref MemoryMarshal.GetReference(result), count);
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
}
