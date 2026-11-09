namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAvx512 on two moduli at once (see IMontgomeryPairKernel): lane 2j of vector v holds digit 4v + j of the first and lane 2j + 1 digit 4v + j of the second, as the words of a pair lie, so that a digit moves by two lanes and every broadcast is one of 128 bits. The vectors do as much for two moduli as they would for one, and the two chains of the scalar side, from a sum to m and back, overlap.
// Each chain keeps lanes 0 to 2 of its modulus and takes lane 3 from the first vector after the low parts, which two iterations separate from its use in m, enough with the chains overlapped to hide the latency of the vectors.
internal readonly unsafe struct MontgomeryPairKernelAvx512<TWindow> : IMontgomeryPairKernel where TWindow : struct, IAvx512Window<TWindow>
{
	private const int R = 52;
	private const int S = 64 - R;

	// The rows of scratch: b as doubles, then the parts of lanes 0 to 3 that come from b.
	private const int Rows = 5;

	private const ulong EvenBits = 0x5555_5555_5555_5555UL;

	public static bool IsSupported => MontgomeryKernelAvx512<Avx512Window>.IsSupported;

	public static int DigitBits => R;

	public static int MinDigitCount => 4;

	// The masks of Normalize hold 96 digits of each.
	public static int MaxDigitCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Math.Min(4 * TWindow.Count, 32 * Avx512Window.MaskWords.Length);
	}

	// Rows of 2·MaxDigitCount words.
	public static int GetScratchLength(int digitCount)
	{
		return Rows * 2 * MaxDigitCount;
	}

	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		Multiply(result, value, value, moduli, firstInverse, secondInverse, scratch);
	}

	// Kept out of its callers and optimized from the first call, with the spans pinned for the masked loads and stores and the broadcasts, as in MontgomeryKernelAvx512.Multiply.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		int words = moduli.Length;
		int row = 2 * MaxDigitCount;

		Debug.Assert(words >= 2 * MinDigitCount && words <= row && result.Length == words && left.Length == words && right.Length == words && scratch.Length >= Rows * row);

		// ReSharper disable UnusedVariable
		fixed (ulong* resultPointer = &MemoryMarshal.GetReference(result))
		fixed (ulong* leftPointer = &MemoryMarshal.GetReference(left))
		fixed (ulong* rightPointer = &MemoryMarshal.GetReference(right))
		fixed (ulong* moduliPointer = &MemoryMarshal.GetReference(moduli))
		fixed (ulong* scratchPointer = &MemoryMarshal.GetReference(scratch))
		// ReSharper restore UnusedVariable
		{
			ref ulong x = ref MemoryMarshal.GetReference(left);
			ref ulong n = ref MemoryMarshal.GetReference(moduli);
			ref ulong rows = ref MemoryMarshal.GetReference(scratch);
			Unsafe.SkipInit(out TWindow a);
			Unsafe.SkipInit(out TWindow nn);
			TWindow.Load(ref a, ref x, words, 0);
			TWindow.Load(ref nn, ref n, words, 0);
			Vector512<double> high = Vector512.Create(BitConverter.UInt64BitsToDouble(Avx512Window.HighBits));
			Vector512<double> low = Vector512.Create(BitConverter.UInt64BitsToDouble(Avx512Window.HighBits + 1));
			Products(ref x, ref MemoryMarshal.GetReference(right), words, ref rows, high, low);

			TWindow acc = default;
			Vector512<ulong> next = Vector512.Create(Avx512Window.LowOffset);
			Vector512<ulong> step = Vector512.Create(Avx512Window.Offset);
			ulong p0 = n;
			ulong q0 = Unsafe.Add(ref n, 1);
			ulong p1 = Unsafe.Add(ref n, 2);
			ulong q1 = Unsafe.Add(ref n, 3);
			ulong p2 = Unsafe.Add(ref n, 4);
			ulong q2 = Unsafe.Add(ref n, 5);
			ulong pInverse = firstInverse << S;
			ulong qInverse = secondInverse << S;
			ulong s0 = 0;
			ulong s1 = 0;
			ulong s2 = 0;
			ulong r0 = 0;
			ulong r1 = 0;
			ulong r2 = 0;

			for (nint i = 0; i < words; i += 2)
			{
				ulong u = s0 + Unsafe.Add(ref rows, row + i);
				ulong v = r0 + Unsafe.Add(ref rows, row + i + 1);
				ulong m = u * pInverse;
				ulong k = v * qInverse;
				Vector512<double> b = Avx512DQ.BroadcastVector128ToVector512((double*)Unsafe.AsPointer(ref Unsafe.Add(ref rows, i)));
				Vector512<ulong> mk = Vector128.Create(m >> S, k >> S).ToVector256Unsafe().ToVector512Unsafe();
				TWindow.Accumulate(ref acc, in a, in nn, b, Avx512DQ.ConvertToVector512Double(Avx512F.Shuffle4x128(mk, mk, 0)), high, low);
				Vector128<ulong> lane3 = Avx512F.ExtractVector128(TWindow.First(in acc) - next, 3);
				TWindow.Shift(ref acc, next);
				next += step;
				s0 = s1 + Unsafe.Add(ref rows, 2 * row + i) + Bmi2.X64.MultiplyNoFlags(m, p0) + (m * p1 >> S) + (u + (m * p0 >> S) >> R);
				s1 = s2 + Unsafe.Add(ref rows, 3 * row + i) + Bmi2.X64.MultiplyNoFlags(m, p1) + (m * p2 >> S);
				s2 = lane3.ToScalar() + Unsafe.Add(ref rows, 4 * row + i) + Bmi2.X64.MultiplyNoFlags(m, p2);
				r0 = r1 + Unsafe.Add(ref rows, 2 * row + i + 1) + Bmi2.X64.MultiplyNoFlags(k, q0) + (k * q1 >> S) + (v + (k * q0 >> S) >> R);
				r1 = r2 + Unsafe.Add(ref rows, 3 * row + i + 1) + Bmi2.X64.MultiplyNoFlags(k, q1) + (k * q2 >> S);
				r2 = lane3.GetElement(1) + Unsafe.Add(ref rows, 4 * row + i + 1) + Bmi2.X64.MultiplyNoFlags(k, q2);
			}

			Vector512<ulong> shared = next - Vector512.Create(Avx512Window.LowOffset);
			TWindow.ReplaceLow(ref acc, Vector512.Create(s0, r0, s1, r1, s2, r2, 0, 0) + shared, Vector512.Create(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 0, 0));
			TWindow.Pass(ref acc, shared, Vector512<ulong>.Zero);
			Normalize(ref acc, ref MemoryMarshal.GetReference(result), words);
		}
	}

	// Row 0: the words of the right operand as doubles. Rows 1 to 4: the parts of lanes 0 to 3 of each modulus that come from them, as Avx512Window.Products takes them, interleaved likewise: lo(a0·b_i), then hi(a_{j−1}·b_i) + lo(a_j·b_i), then hi(a2·b_i).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Products(ref ulong x, ref ulong y, int words, ref ulong rows, Vector512<double> high, Vector512<double> low)
	{
		int row = 2 * MaxDigitCount;
		Vector512<double> a0 = Vector512.Create(Avx512DQ.VL.ConvertToVector128Double(Vector128.LoadUnsafe(ref x)));
		Vector512<double> a1 = Vector512.Create(Avx512DQ.VL.ConvertToVector128Double(Vector128.LoadUnsafe(ref x, 2)));
		Vector512<double> a2 = Vector512.Create(Avx512DQ.VL.ConvertToVector128Double(Vector128.LoadUnsafe(ref x, 4)));
		Vector512<ulong> highBits = Vector512.Create(Avx512Window.HighBits);
		Vector512<ulong> lowBits = Vector512.Create(Avx512Window.LowBits);

		for (int j = 0; j < words; j += 8)
		{
			Vector512<ulong> lanes = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Min(words - j, 8)));
			Vector512<double> b = Avx512DQ.ConvertToVector512Double(Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref y, j)), lanes, Vector512<ulong>.Zero));
			Vector512<double> t0 = Avx512F.FusedMultiplyAdd(a0, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a1, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t2 = Avx512F.FusedMultiplyAdd(a2, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<ulong> l0 = Avx512F.FusedMultiplyAdd(a0, b, low - t0).AsUInt64() - lowBits;
			Vector512<ulong> l1 = Avx512F.FusedMultiplyAdd(a1, b, low - t1).AsUInt64() - lowBits;
			Vector512<ulong> l2 = Avx512F.FusedMultiplyAdd(a2, b, low - t2).AsUInt64() - lowBits;
			Avx512Window.StoreLanes(b.AsUInt64(), ref rows, j, lanes);
			Avx512Window.StoreLanes(l0, ref rows, row + j, lanes);
			Avx512Window.StoreLanes(t0.AsUInt64() - highBits + l1, ref rows, 2 * row + j, lanes);
			Avx512Window.StoreLanes(t1.AsUInt64() - highBits + l2, ref rows, 3 * row + j, lanes);
			Avx512Window.StoreLanes(t2.AsUInt64() - highBits, ref rows, 4 * row + j, lanes);
		}
	}

	// The ripple of Avx512Window.Normalize for each modulus on its own lanes, the even ones or the odd ones: the lanes of the other modulus count as lanes that pass a carry on, and the generated carries start in them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Normalize(ref TWindow acc, ref ulong result, int words)
	{
		int maskWords = (words + 63) / 64;
		Avx512Window.MaskWords generateWords = default;
		Avx512Window.MaskWords propagateWords = default;
		Span<ulong> generate = generateWords;
		Span<ulong> propagate = propagateWords;
		TWindow.Masks(in acc, 0, generate, propagate);
		ulong evenCarry = 0;
		ulong oddCarry = 0;

		for (int w = 0; w < maskWords; ++w)
		{
			ulong evenShifted = (generate[w] & EvenBits) << 1 | evenCarry;
			ulong evenPropagate = propagate[w] | ~EvenBits;
			ulong evenSum = evenShifted + evenPropagate;
			evenCarry = (evenShifted & evenPropagate | (evenShifted | evenPropagate) & ~evenSum) >> 63;
			ulong oddShifted = (generate[w] & ~EvenBits) << 1 | oddCarry;
			ulong oddPropagate = propagate[w] | EvenBits;
			ulong oddSum = oddShifted + oddPropagate;
			oddCarry = generate[w] >> 63 | (oddShifted & oddPropagate | (oddShifted | oddPropagate) & ~oddSum) >> 63;
			generate[w] = (evenSum ^ evenPropagate) & EvenBits | (oddSum ^ oddPropagate) & ~EvenBits;
		}

		TWindow.Store(in acc, 0, generate, ref result, words);
		// Erased, as the scratch is.
		generate.ZeroMemory();
		propagate.ZeroMemory();
	}
}
