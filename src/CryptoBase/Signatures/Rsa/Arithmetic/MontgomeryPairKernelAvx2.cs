namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAvx2 on two moduli at once (see IMontgomeryPairKernel): lane 2j of vector v holds digit 2v + j of the first and lane 2j + 1 digit 2v + j of the second, as the words of a pair lie, so that a digit moves by half a vector and every broadcast is one of 128 bits. The vectors do as much for two moduli as they would for one, and the two chains of the scalar side, from a sum to m and back, overlap.
// Each chain keeps digits 0 to 2 of its modulus, so that the vectors leave out vector 0, and takes digit 3 from the upper half of vector 1. The window, the staging and the rows are those of MontgomeryKernelAvx2, with the words of the two moduli interleaved in each.
internal readonly unsafe struct MontgomeryPairKernelAvx2<TWindow> : IMontgomeryPairKernel where TWindow : struct, IAvx2PairWindow<TWindow>
{
	private const int R = 51;
	private const int S = 64 - R;
	private const ulong Mask = (1UL << R) - 1;

	// A row: b_i of each modulus as a double, then the parts of lanes 0 to 3 of each that come from b_i, and two words of padding.
	private const int RowWords = 12;

	// As in MontgomeryKernelAvx2.
	private const ulong HighBits = 0x4660000000000000UL;
	private const ulong LowBits = 0x4338000000000000UL;
	private const ulong LowOffset = 2 * LowBits;
	private const ulong Offset = unchecked(2 * LowBits + 2 * HighBits);

	public static bool IsSupported => MontgomeryKernelAvx2<Avx2Window>.IsSupported;

	public static int DigitBits => R;

	public static int MinDigitCount => 4;

	public static int MaxDigitCount => MontgomeryKernelAvx2<Avx2Window>.MaxDigitCount;

	// The rows of two digits of each modulus per vector, the blocks past vector 0, and the room to align them; the rows take the lanes at the end.
	public static int GetScratchLength(int digitCount)
	{
		int vectors = GetVectors(digitCount);
		return 2 * RowWords * vectors + Avx2Window.BlockWords * (vectors - 1) + 8;
	}

	// At least the window and vector 0.
	private static int GetVectors(int digitCount)
	{
		return Math.Max(digitCount + 1 >> 1, TWindow.Count + 1);
	}

	public static void Prepare(ReadOnlySpan<ulong> first, ReadOnlySpan<ulong> second, Span<ulong> moduli)
	{
		Debug.Assert(first.Length == second.Length && moduli.Length == 2 * first.Length);

		for (int i = 0; i < first.Length; ++i)
		{
			moduli[2 * i] = first[i];
			moduli[2 * i + 1] = second[i];
		}
	}

	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		Multiply(result, value, value, moduli, firstInverse, secondInverse, scratch);
	}

	// Kept out of its callers and optimized from the first call, as MontgomeryKernelAvx2.Multiply, with the scratch pinned as well for the broadcasts from the rows.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		int words = moduli.Length;
		int digits = words >> 1;
		int vectors = GetVectors(digits);

		Debug.Assert(digits >= MinDigitCount && digits <= MaxDigitCount && result.Length == words && left.Length == words && right.Length == words && scratch.Length >= GetScratchLength(digits));

		// ReSharper disable UnusedVariable
		fixed (ulong* leftPointer = &MemoryMarshal.GetReference(left))
		fixed (ulong* rightPointer = &MemoryMarshal.GetReference(right))
		fixed (ulong* moduliPointer = &MemoryMarshal.GetReference(moduli))
		fixed (ulong* scratchPointer = &MemoryMarshal.GetReference(scratch))
		// ReSharper restore UnusedVariable
		{
			ref ulong x = ref MemoryMarshal.GetReference(left);
			ref ulong n = ref MemoryMarshal.GetReference(moduli);
			ref ulong rows = ref MemoryMarshal.GetReference(scratch);
			ref ulong staging = ref Stage(ref x, ref n, words, vectors, ref Unsafe.Add(ref rows, 2 * RowWords * vectors));
			Vector256<double> high = Vector256.Create(BitConverter.UInt64BitsToDouble(HighBits));
			Vector256<double> low = Vector256.Create(BitConverter.UInt64BitsToDouble(HighBits + 3));
			Products(ref x, ref MemoryMarshal.GetReference(right), words, ref rows, high, low);

			TWindow acc = default;
			Vector256<ulong> next = Vector256.Create(LowOffset);
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
			ref ulong row = ref rows;
			ref ulong end = ref Unsafe.Add(ref rows, RowWords * digits);
			ref ulong window = ref Unsafe.Add(ref staging, Avx2Window.BlockWords * (TWindow.Count - 1));
			nint top = Avx2Window.BlockWords * (vectors - 1 - TWindow.Count);

			do
			{
				ulong u = s0 + Unsafe.Add(ref row, 2);
				ulong v = r0 + Unsafe.Add(ref row, 3);
				ulong m = u * pInverse;
				ulong k = v * qInverse;
				Vector256<double> b = Avx.BroadcastVector128ToVector256((double*)Unsafe.AsPointer(ref row));
				Vector128<double> mk = Vector128.Create(ToDouble(m >> S), ToDouble(k >> S));
				Vector256<double> d = Vector256.Create(mk, mk);
				Vector256<ulong> above = next;

				for (nint j = top; j > 0; j -= Avx2Window.BlockWords)
				{
					Vector256<ulong> sums = Avx2Window.Accumulate(ref window, j, Vector256.LoadUnsafe(ref window, (nuint)(j + 8)), b, d, high, low, out Vector256<ulong> highParts);
					Avx2PairWindow.Shift(sums, above, highParts).StoreUnsafe(ref window, (nuint)(j + 8));
					above = sums;
				}

				Vector128<ulong> digit3 = TWindow.Step(ref acc, ref staging, 0, above, b, d, high, low).GetUpper() - next.GetLower();
				next += Vector256.Create(Offset);
				s0 = s1 + Unsafe.Add(ref row, 4) + Bmi2.X64.MultiplyNoFlags(m, p0) + (m * p1 >> S) + (ulong)((long)(u + (m * p0 >> S)) >> R);
				r0 = r1 + Unsafe.Add(ref row, 5) + Bmi2.X64.MultiplyNoFlags(k, q0) + (k * q1 >> S) + (ulong)((long)(v + (k * q0 >> S)) >> R);
				s1 = s2 + Unsafe.Add(ref row, 6) + Bmi2.X64.MultiplyNoFlags(m, p1) + (m * p2 >> S);
				r1 = r2 + Unsafe.Add(ref row, 7) + Bmi2.X64.MultiplyNoFlags(k, q1) + (k * q2 >> S);
				s2 = digit3.ToScalar() + Unsafe.Add(ref row, 8) + Bmi2.X64.MultiplyNoFlags(m, p2);
				r2 = digit3.GetElement(1) + Unsafe.Add(ref row, 9) + Bmi2.X64.MultiplyNoFlags(k, q2);
				row = ref Unsafe.Add(ref row, RowWords);
			}
			while (Unsafe.IsAddressLessThan(ref row, ref end));

			// The lanes less their offset into the rows, as MontgomeryKernelAvx2 takes them, with digits 0 to 2 of each modulus from the scalar side.
			Vector256<ulong> shared = next - Vector256.Create(LowOffset);
			TWindow.Store(in acc, ref Unsafe.Add(ref rows, 4), shared);

			for (nint w = TWindow.Count + 1; w < vectors; ++w)
			{
				(Vector256.LoadUnsafe(ref staging, (nuint)(Avx2Window.BlockWords * (w - 1) + 8)) - shared).StoreUnsafe(ref rows, (nuint)(4 * w));
			}

			rows = s0;
			Unsafe.Add(ref rows, 1) = r0;
			Unsafe.Add(ref rows, 2) = s1;
			Unsafe.Add(ref rows, 3) = r1;
			Unsafe.Add(ref rows, 4) = s2;
			Unsafe.Add(ref rows, 5) = r2;
			ref ulong output = ref MemoryMarshal.GetReference(result);
			long firstCarry = 0;
			long secondCarry = 0;

			for (nint i = 0; i < words; i += 2)
			{
				long firstDigit = (long)Unsafe.Add(ref rows, i) + firstCarry;
				long secondDigit = (long)Unsafe.Add(ref rows, i + 1) + secondCarry;
				Unsafe.Add(ref output, i) = (ulong)firstDigit & Mask;
				Unsafe.Add(ref output, i + 1) = (ulong)secondDigit & Mask;
				firstCarry = firstDigit >> R;
				secondCarry = secondDigit >> R;
			}
		}
	}

	// The blocks of MontgomeryKernelAvx2.Stage, of interleaved words.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref ulong Stage(ref ulong x, ref ulong n, int words, int vectors, ref ulong start)
	{
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		ref ulong staging = ref Unsafe.AddByteOffset(ref start, (address + 63 & ~(nuint)63) - address);

		for (int v = 1; v < vectors; ++v)
		{
			Vector256<ulong> lanes = Vector256.LessThan(Vector256.Create(0UL, 1, 2, 3), Vector256.Create((ulong)Math.Clamp(words - 4 * v, 0, 4)));
			ref ulong block = ref Unsafe.Add(ref staging, Avx2Window.BlockWords * (v - 1));
			Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref x, 4 * v)), lanes)).AsUInt64().StoreUnsafe(ref block);
			Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref n, 4 * v)), lanes)).AsUInt64().StoreUnsafe(ref block, 4);
			Vector256<ulong>.Zero.StoreUnsafe(ref block, 8);
		}

		return ref staging;
	}

	// The row of each digit: b of each modulus as a double, then the parts of lanes 0 to 3 of each that come from it, as MontgomeryPairKernelAvx512.Products takes them, interleaved likewise: lo(a0·b_i), then hi(a_{j−1}·b_i) + lo(a_j·b_i), then hi(a2·b_i). Two digits of each modulus at a time.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Products(ref ulong x, ref ulong y, int words, ref ulong rows, Vector256<double> high, Vector256<double> low)
	{
		Vector128<double> x0 = Vector128.Create(ToDouble(x), ToDouble(Unsafe.Add(ref x, 1)));
		Vector128<double> x1 = Vector128.Create(ToDouble(Unsafe.Add(ref x, 2)), ToDouble(Unsafe.Add(ref x, 3)));
		Vector128<double> x2 = Vector128.Create(ToDouble(Unsafe.Add(ref x, 4)), ToDouble(Unsafe.Add(ref x, 5)));
		Vector256<double> a0 = Vector256.Create(x0, x0);
		Vector256<double> a1 = Vector256.Create(x1, x1);
		Vector256<double> a2 = Vector256.Create(x2, x2);
		Vector256<ulong> highBits = Vector256.Create(HighBits);
		Vector256<ulong> lowBits = Vector256.Create(LowBits);

		for (int j = 0; j < words; j += 4)
		{
			Vector256<ulong> lanes = Vector256.LessThan(Vector256.Create(0UL, 1, 2, 3), Vector256.Create((ulong)Math.Min(words - j, 4)));
			Vector256<double> b = Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref y, j)), lanes));
			Vector256<double> t0 = Fma.MultiplyAdd(a0, b, high);
			Vector256<double> t1 = Fma.MultiplyAdd(a1, b, high);
			Vector256<double> t2 = Fma.MultiplyAdd(a2, b, high);
			Vector256<ulong> l0 = Fma.MultiplyAdd(a0, b, low - t0).AsUInt64() - lowBits;
			Vector256<ulong> l1 = Fma.MultiplyAdd(a1, b, low - t1).AsUInt64() - lowBits;
			Vector256<ulong> l2 = Fma.MultiplyAdd(a2, b, low - t2).AsUInt64() - lowBits;
			Vector256<ulong> part2 = t0.AsUInt64() - highBits + l1;
			Vector256<ulong> part3 = t1.AsUInt64() - highBits + l2;
			Vector256<ulong> part4 = t2.AsUInt64() - highBits;
			ref ulong row = ref Unsafe.Add(ref rows, RowWords / 2 * j);
			Avx2.Permute2x128(b.AsUInt64(), l0, 0x20).StoreUnsafe(ref row);
			Avx2.Permute2x128(part2, part3, 0x20).StoreUnsafe(ref row, 4);
			part4.GetLower().StoreUnsafe(ref row, 8);
			Avx2.Permute2x128(b.AsUInt64(), l0, 0x31).StoreUnsafe(ref row, RowWords);
			Avx2.Permute2x128(part2, part3, 0x31).StoreUnsafe(ref row, RowWords + 4);
			part4.GetUpper().StoreUnsafe(ref row, RowWords + 8);
		}
	}

	// A digit, below 2^52, through the signed conversion, which takes one instruction.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static double ToDouble(ulong digit)
	{
		return (long)digit;
	}
}
