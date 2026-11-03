namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAvx512 on AVX2 and FMA, with four lanes per vector and rounding to nearest, the only mode of FMA there. Digits have 51 bits, so that every constant of the split is exact:
//   t = fma(a, b, 2^103) = 2^103 + h with h = a·b rounded to a multiple of 2^51, whose bits less those of 2^103 are the high digit h/2^51, from 0 to 2^51;
//   fma(a, b, (2^103 + 1.5·2^52) − t) = a·b − h + 1.5·2^52, in [2^52, 2^53), whose bits less those of 1.5·2^52 are the low digit a·b − h, from −2^50 to 2^50.
// The lanes therefore hold signed sums, and the scalar side shifts its carries arithmetically. Each product splits one way on the vector and the other way on the scalar side, which keeps the parts of its own products: both ways sum to the product. As AVX2 shifts no 64-bit lane arithmetically, the digits ripple out on the scalar side at the end.
// The scalar side keeps lanes 0 to 3, all of vector 0, which the vectors therefore leave out, and takes lane 4 from vector 1. Vectors 1 to TWindow.Count of the accumulator stay in registers, and any past them in staging with the operands: staging starts on a 64-byte boundary and holds a block per vector from vector 1 up, of the digits of the left operand and of the modulus as doubles and of the lanes of a vector past the window, so that no vector crosses a cache line and none spills to a stack aligned for half of one. For each digit of the right operand the vectors run from the top down, each shifting in lane 0 of the one above it after the low parts.
// The parts of lanes 0 to 4 that come from b_i lie in rows, a row of the words of each digit, so that the scalar side reads them from one pointer.
internal readonly unsafe struct MontgomeryKernelAvx2<TWindow> : IMontgomeryKernel where TWindow : struct, IAvx2Window<TWindow>
{
	private const int R = 51;
	private const int S = 64 - R;
	private const ulong Mask = (1UL << R) - 1;

	// A row: b_i as a double, then the parts of lanes 0 to 4 that come from b_i, and two words of padding.
	private const int RowWords = 8;

	// The bits of 2^103 and of 1.5·2^52; the lane shifted in at iteration i carries LowOffset + i·Offset, as in MontgomeryKernelAvx512.
	private const ulong HighBits = 0x4660000000000000UL;
	private const ulong LowBits = 0x4338000000000000UL;
	private const ulong LowOffset = 2 * LowBits;
	private const ulong Offset = unchecked(2 * LowBits + 2 * HighBits);

	public static bool IsSupported => Vector256.IsHardwareAccelerated && Avx2.IsSupported && Fma.IsSupported && Bmi2.X64.IsSupported;

	public static int DigitBits => R;

	// A lane gains less than 2^53 in magnitude per iteration, so the sums stay within 2^63.
	public static int MaxDigitCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1023;
	}

	// The rows of four digits per vector, the blocks past vector 0, and the room to align them; the rows take the lanes at the end.
	public static int GetScratchLength(int digitCount)
	{
		int vectors = GetVectors(digitCount);
		return 4 * RowWords * vectors + Avx2Window.BlockWords * (vectors - 1) + 8;
	}

	// At least the window and vector 0.
	private static int GetVectors(int digitCount)
	{
		return Math.Max(digitCount + 3 >> 2, TWindow.Count + 1);
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		modulus.CopyTo(prepared);
	}

	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		Multiply(result, value, value, modulus, negativeInverse, scratch);
	}

	// Kept out of its callers, where the window methods would no longer inline and the window would leave the registers, and optimized from the first call. The masked loads take pointers into the operands, which stay pinned as in MontgomeryKernelAvx512.Multiply.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int count = modulus.Length;
		int vectors = GetVectors(count);

		Debug.Assert(count <= MaxDigitCount && result.Length == count && left.Length == count && right.Length == count && scratch.Length >= GetScratchLength(count));

		// ReSharper disable UnusedVariable
		fixed (ulong* leftPointer = &MemoryMarshal.GetReference(left))
		fixed (ulong* rightPointer = &MemoryMarshal.GetReference(right))
		fixed (ulong* modulusPointer = &MemoryMarshal.GetReference(modulus))
		// ReSharper restore UnusedVariable
		{
			ref ulong x = ref MemoryMarshal.GetReference(left);
			ref ulong n = ref MemoryMarshal.GetReference(modulus);
			ref ulong rows = ref MemoryMarshal.GetReference(scratch);
			ref ulong staging = ref Stage(ref x, ref n, count, vectors, ref Unsafe.Add(ref rows, 4 * RowWords * vectors));
			Vector256<double> high = Vector256.Create(BitConverter.UInt64BitsToDouble(HighBits));
			Vector256<double> low = Vector256.Create(BitConverter.UInt64BitsToDouble(HighBits + 3));
			Products(ref x, ref MemoryMarshal.GetReference(right), count, ref rows, high, low);

			TWindow acc = default;
			Vector256<ulong> next = Vector256.Create(LowOffset);
			ulong n0 = n;
			ulong n1 = Digit(ref n, count, 1);
			ulong n2 = Digit(ref n, count, 2);
			ulong n3 = Digit(ref n, count, 3);
			// u·(−n⁻¹·2^13) mod 2^64 is m·2^13.
			ulong inverse = negativeInverse << S;
			ulong s0 = 0;
			ulong s1 = 0;
			ulong s2 = 0;
			ulong s3 = 0;
			ref ulong row = ref rows;
			ref ulong end = ref Unsafe.Add(ref rows, RowWords * count);
			// The vectors past the window, from the top vector of the window.
			ref ulong window = ref Unsafe.Add(ref staging, Avx2Window.BlockWords * (TWindow.Count - 1));
			nint top = Avx2Window.BlockWords * (vectors - 1 - TWindow.Count);

			do
			{
				ulong u = s0 + Unsafe.Add(ref row, 1);
				ulong m = u * inverse;
				Vector256<double> b = Vector256.Create(Unsafe.As<ulong, double>(ref row));
				Vector256<double> d = Vector256.Create((double)(long)(m >> S));
				Vector256<ulong> above = next;

				for (nint k = top; k > 0; k -= Avx2Window.BlockWords)
				{
					Vector256<ulong> sums = Avx2Window.Accumulate(ref window, k, Vector256.LoadUnsafe(ref window, (nuint)(k + 8)), b, d, high, low, out Vector256<ulong> highParts);
					Avx2Window.Shift(sums, above, highParts).StoreUnsafe(ref window, (nuint)(k + 8));
					above = sums;
				}

				// The lanes before the shift carry the offset that the lane shifted in starts with.
				ulong lane4 = (TWindow.Step(ref acc, ref staging, 0, above, b, d, high, low) - next).ToScalar();
				next += Vector256.Create(Offset);
				// Each lane from the one above it, so that no old lane outlives the new one below it.
				s0 = s1 + Unsafe.Add(ref row, 2) + Bmi2.X64.MultiplyNoFlags(m, n0) + (m * n1 >> S) + (ulong)((long)(u + (m * n0 >> S)) >> R);
				s1 = s2 + Unsafe.Add(ref row, 3) + Bmi2.X64.MultiplyNoFlags(m, n1) + (m * n2 >> S);
				s2 = s3 + Unsafe.Add(ref row, 4) + Bmi2.X64.MultiplyNoFlags(m, n2) + (m * n3 >> S);
				s3 = lane4 + Unsafe.Add(ref row, 5) + Bmi2.X64.MultiplyNoFlags(m, n3);
				row = ref Unsafe.Add(ref row, RowWords);
			}
			while (Unsafe.IsAddressLessThan(ref row, ref end));

			// The lanes less their offset into the rows, which the loop no longer reads, with those of vector 0 from the scalar side.
			Vector256<ulong> shared = next - Vector256.Create(LowOffset);
			TWindow.Store(in acc, ref Unsafe.Add(ref rows, 4), shared);

			for (nint v = TWindow.Count + 1; v < vectors; ++v)
			{
				(Vector256.LoadUnsafe(ref staging, (nuint)(Avx2Window.BlockWords * (v - 1) + 8)) - shared).StoreUnsafe(ref rows, (nuint)(4 * v));
			}

			rows = s0;
			Unsafe.Add(ref rows, 1) = s1;
			Unsafe.Add(ref rows, 2) = s2;
			Unsafe.Add(ref rows, 3) = s3;
			ref ulong output = ref MemoryMarshal.GetReference(result);
			long carry = 0;

			for (nint j = 0; j < count; ++j)
			{
				long digit = (long)Unsafe.Add(ref rows, j) + carry;
				Unsafe.Add(ref output, j) = (ulong)digit & Mask;
				carry = digit >> R;
			}
		}
	}

	// The blocks of vectors 1 and up from the first 64-byte boundary at or after start, which it returns, with the lanes zero. If the scratch moves meanwhile, only the speed changes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref ulong Stage(ref ulong x, ref ulong n, int count, int vectors, ref ulong start)
	{
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		ref ulong staging = ref Unsafe.AddByteOffset(ref start, (address + 63 & ~(nuint)63) - address);

		for (int v = 1; v < vectors; ++v)
		{
			Vector256<ulong> lanes = Vector256.LessThan(Vector256.Create(0UL, 1, 2, 3), Vector256.Create((ulong)Math.Clamp(count - 4 * v, 0, 4)));
			ref ulong block = ref Unsafe.Add(ref staging, Avx2Window.BlockWords * (v - 1));
			Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref x, 4 * v)), lanes)).AsUInt64().StoreUnsafe(ref block);
			Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref n, 4 * v)), lanes)).AsUInt64().StoreUnsafe(ref block, 4);
			Vector256<ulong>.Zero.StoreUnsafe(ref block, 8);
		}

		return ref staging;
	}

	// The row of each digit b_i of the right operand: b_i as a double, then the parts of its products with the first four digits of the left one that lanes 0 to 4 gain at iteration i, lo(a0·b_i), then hi(a_{j−1}·b_i) + lo(a_j·b_i), then hi(a3·b_i). Four digits at a time, transposed from vectors of a part each.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Products(ref ulong x, ref ulong y, int count, ref ulong rows, Vector256<double> high, Vector256<double> low)
	{
		Vector256<double> a0 = Vector256.Create((double)(long)x);
		Vector256<double> a1 = Vector256.Create((double)(long)Digit(ref x, count, 1));
		Vector256<double> a2 = Vector256.Create((double)(long)Digit(ref x, count, 2));
		Vector256<double> a3 = Vector256.Create((double)(long)Digit(ref x, count, 3));
		Vector256<ulong> highBits = Vector256.Create(HighBits);
		Vector256<ulong> lowBits = Vector256.Create(LowBits);

		for (int j = 0; j < count; j += 4)
		{
			Vector256<ulong> lanes = Vector256.LessThan(Vector256.Create(0UL, 1, 2, 3), Vector256.Create((ulong)Math.Min(count - j, 4)));
			Vector256<double> b = Avx2Window.ToDouble(Avx2.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref y, j)), lanes));
			Vector256<double> t0 = Fma.MultiplyAdd(a0, b, high);
			Vector256<double> t1 = Fma.MultiplyAdd(a1, b, high);
			Vector256<double> t2 = Fma.MultiplyAdd(a2, b, high);
			Vector256<double> t3 = Fma.MultiplyAdd(a3, b, high);
			Vector256<ulong> l0 = Fma.MultiplyAdd(a0, b, low - t0).AsUInt64() - lowBits;
			Vector256<ulong> l1 = Fma.MultiplyAdd(a1, b, low - t1).AsUInt64() - lowBits;
			Vector256<ulong> l2 = Fma.MultiplyAdd(a2, b, low - t2).AsUInt64() - lowBits;
			Vector256<ulong> l3 = Fma.MultiplyAdd(a3, b, low - t3).AsUInt64() - lowBits;
			Vector256<ulong> part2 = t0.AsUInt64() - highBits + l1;
			Vector256<ulong> part3 = t1.AsUInt64() - highBits + l2;
			Vector256<ulong> part4 = t2.AsUInt64() - highBits + l3;
			Vector256<ulong> part5 = t3.AsUInt64() - highBits;
			Vector256<ulong> even01 = Avx2.UnpackLow(b.AsUInt64(), l0);
			Vector256<ulong> odd01 = Avx2.UnpackHigh(b.AsUInt64(), l0);
			Vector256<ulong> even23 = Avx2.UnpackLow(part2, part3);
			Vector256<ulong> odd23 = Avx2.UnpackHigh(part2, part3);
			Vector256<ulong> even45 = Avx2.UnpackLow(part4, part5);
			Vector256<ulong> odd45 = Avx2.UnpackHigh(part4, part5);
			ref ulong row = ref Unsafe.Add(ref rows, RowWords * j);
			Avx2.Permute2x128(even01, even23, 0x20).StoreUnsafe(ref row);
			even45.GetLower().StoreUnsafe(ref row, 4);
			Avx2.Permute2x128(odd01, odd23, 0x20).StoreUnsafe(ref row, RowWords);
			odd45.GetLower().StoreUnsafe(ref row, RowWords + 4);
			Avx2.Permute2x128(even01, even23, 0x31).StoreUnsafe(ref row, 2 * RowWords);
			even45.GetUpper().StoreUnsafe(ref row, 2 * RowWords + 4);
			Avx2.Permute2x128(odd01, odd23, 0x31).StoreUnsafe(ref row, 3 * RowWords);
			odd45.GetUpper().StoreUnsafe(ref row, 3 * RowWords + 4);
		}
	}

	// Digit index of a value of count digits, zero past them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Digit(ref ulong digits, int count, int index)
	{
		return index < count ? Unsafe.Add(ref digits, index) : 0;
	}
}
