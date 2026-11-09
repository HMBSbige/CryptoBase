namespace CryptoBase.Signatures.Rsa.Arithmetic;

// MontgomeryKernelAdvSimd on two moduli at once (see IMontgomeryPairKernel), the first in lane 0 and the second in lane 1 of every sum: umlal and umlal2 take a pair of 32-bit words, a digit of each modulus, from each operand, so that each instruction makes a product for each modulus and the reduction of a block runs once for both.
// Operands are pairs of words, the left one and m ascending and the right one and n descending, so that a column is a dot product of the left operand with the right one at an offset, both ascending: the lower halves of two quads give the products of pair i and the upper halves those of pair i + 1. Blocks of four columns take the quads of the right operand at four offsets, two of which the next two pairs reuse.
// A square takes the cross products below the diagonal once, from a doubled copy of the operand, and the squares on it from the plain copy, in the group around the diagonal; the reductions go on alone from there.
// The tails and the bounds of the sums are those of MontgomeryKernelAdvSimd, and so is the placement of the operands, each within a page where it fits.
internal readonly struct MontgomeryPairKernelAdvSimd<TRadix> : IMontgomeryPairKernel where TRadix : struct, IRadix
{
	// Pairs of zeros on either side of each operand, more than a block reads past the ends.
	private const int Pad = 8;

	public static bool IsSupported => MontgomeryKernelAdvSimd<TRadix>.IsSupported;

	public static int DigitBits => TRadix.Bits;

	public static int MinDigitCount => 4;

	public static int MaxDigitCount => MontgomeryKernelAdvSimd<TRadix>.MaxDigitCount;

	// Five operands of digitCount pairs with their zeros, a, b reversed, n reversed and m for a product, and a, a reversed, 2·a reversed, n reversed and m for a square, each of which Place may move by as much as it takes and 15 bytes.
	public static int GetScratchLength(int digitCount)
	{
		return 10 * (digitCount + 2 * Pad) + 10;
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		int digits = moduli.Length / 2;

		Debug.Assert(digits >= MinDigitCount && result.Length == 2 * digits && left.Length == 2 * digits && right.Length == 2 * digits && scratch.Length >= GetScratchLength(digits));

		int stride = 2 * (digits + 2 * Pad);
		ref uint a = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.As<ulong, uint>(ref MemoryMarshal.GetReference(scratch)), stride, 2 * Pad);
		ref uint b = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref a, stride - 2 * Pad), stride, 2 * Pad);
		ref uint n = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref b, stride - 2 * Pad), stride, 2 * Pad);
		ref uint m = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref n, stride - 2 * Pad), stride, 2 * Pad);
		Narrow(left, ref a, digits, false, 0);
		Narrow(right, ref b, digits, true, 0);
		Narrow(moduli, ref n, digits, true, 0);
		// The pairs of m past digitCount are zero, so that the last blocks may read them.
		ClearPad(ref Unsafe.Add(ref m, 2 * digits));
		MultiplyCore(result, ref a, ref b, ref n, ref m, moduli, Vector64.Create((uint)firstInverse, (uint)secondInverse), digits);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> moduli, ulong firstInverse, ulong secondInverse, Span<ulong> scratch)
	{
		int digits = moduli.Length / 2;

		Debug.Assert(digits >= MinDigitCount && result.Length == 2 * digits && value.Length == 2 * digits && scratch.Length >= GetScratchLength(digits));

		int stride = 2 * (digits + 2 * Pad);
		ref uint a = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.As<ulong, uint>(ref MemoryMarshal.GetReference(scratch)), stride, 2 * Pad);
		ref uint reversed = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref a, stride - 2 * Pad), stride, 2 * Pad);
		ref uint twice = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref reversed, stride - 2 * Pad), stride, 2 * Pad);
		ref uint n = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref twice, stride - 2 * Pad), stride, 2 * Pad);
		ref uint m = ref MontgomeryKernelAdvSimd<TRadix>.Place(ref Unsafe.Add(ref n, stride - 2 * Pad), stride, 2 * Pad);
		Narrow(value, ref a, digits, false, 0);
		Narrow(value, ref reversed, digits, true, 0);
		Narrow(value, ref twice, digits, true, 1);
		Narrow(moduli, ref n, digits, true, 0);
		ClearPad(ref Unsafe.Add(ref m, 2 * digits));
		SquareCore(result, ref a, ref reversed, ref twice, ref n, ref m, moduli, Vector64.Create((uint)firstInverse, (uint)secondInverse), digits);
	}

	// The pairs of digits as pairs of words shifted left by shift, backwards if reversed, with Pad pairs of zeros on either side.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Narrow(ReadOnlySpan<ulong> pairs, ref uint words, int digits, bool reversed, int shift)
	{
		ref ulong source = ref MemoryMarshal.GetReference(pairs);

		for (int i = 0; i < digits; ++i)
		{
			int j = reversed ? digits - 1 - i : i;
			Vector128<uint> pair = Vector128.Narrow(Vector128.LoadUnsafe(ref source, (nuint)(2 * i)), Vector128<ulong>.Zero);
			(pair << shift).GetLower().StoreUnsafe(ref words, (nuint)(2 * j));
		}

		ClearPad(ref Unsafe.Subtract(ref words, 2 * Pad));
		ClearPad(ref Unsafe.Add(ref words, 2 * digits));
	}

	private static void ClearPad(ref uint start)
	{
		for (int i = 0; i < 2 * Pad; i += 4)
		{
			Vector128<uint>.Zero.StoreUnsafe(ref start, (nuint)i);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Load(ref uint words, int pair)
	{
		return Vector128.LoadUnsafe(ref words, (nuint)(2 * pair));
	}

	// Block k has the columns k to k + 3. Below digitCount it takes the pairs i from 0 to k − 1 for both products and k to k + 3 for a·b alone, whose digits m the tail finds; from digitCount on, i from k − digitCount + 1, rounded down to an even pair, to digitCount, rounded up, which the zeros allow.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void MultiplyCore(Span<ulong> result, ref uint a, ref uint b, ref uint n, ref uint m, ReadOnlySpan<ulong> moduli, Vector64<uint> inverse, int digits)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		ref ulong output = ref MemoryMarshal.GetReference(result);
		Vector128<ulong> carry = Vector128<ulong>.Zero;

		for (int k = 0; k < 2 * digits; k += 4)
		{
			Vector128<ulong> ab0 = default, ab1 = default, ab2 = default, ab3 = default, ab4 = default, ab5 = default, ab6 = default, ab7 = default;
			Vector128<ulong> mn0 = default, mn1 = default, mn2 = default, mn3 = default, mn4 = default, mn5 = default, mn6 = default, mn7 = default;
			int start = k < digits ? 0 : k - digits + 1 & ~1;
			int both = Math.Min(k, digits + 1 & ~1);
			// Column k + j takes pair i of a with pair i + offset − j of the reversed operands.
			int offset = digits - 1 - k;
			int i = start;
			Vector128<uint> b0 = Load(ref b, i + offset);
			Vector128<uint> b1 = Load(ref b, i + offset - 1);
			Vector128<uint> b2 = Load(ref b, i + offset - 2);
			Vector128<uint> b3 = Load(ref b, i + offset - 3);
			Vector128<uint> n0 = Load(ref n, i + offset);
			Vector128<uint> n1 = Load(ref n, i + offset - 1);
			Vector128<uint> n2 = Load(ref n, i + offset - 2);
			Vector128<uint> n3 = Load(ref n, i + offset - 3);

			for (; i < both; i += 2)
			{
				Vector128<uint> x = Vector128.LoadUnsafe(ref a, (nuint)(2 * i));
				Vector128<uint> u = Vector128.LoadUnsafe(ref m, (nuint)(2 * i));
				ab0 = AdvSimd.MultiplyWideningLowerAndAdd(ab0, x.GetLower(), b0.GetLower());
				ab1 = AdvSimd.MultiplyWideningUpperAndAdd(ab1, x, b0);
				mn0 = AdvSimd.MultiplyWideningLowerAndAdd(mn0, u.GetLower(), n0.GetLower());
				mn1 = AdvSimd.MultiplyWideningUpperAndAdd(mn1, u, n0);
				ab2 = AdvSimd.MultiplyWideningLowerAndAdd(ab2, x.GetLower(), b1.GetLower());
				ab3 = AdvSimd.MultiplyWideningUpperAndAdd(ab3, x, b1);
				mn2 = AdvSimd.MultiplyWideningLowerAndAdd(mn2, u.GetLower(), n1.GetLower());
				mn3 = AdvSimd.MultiplyWideningUpperAndAdd(mn3, u, n1);
				ab4 = AdvSimd.MultiplyWideningLowerAndAdd(ab4, x.GetLower(), b2.GetLower());
				ab5 = AdvSimd.MultiplyWideningUpperAndAdd(ab5, x, b2);
				mn4 = AdvSimd.MultiplyWideningLowerAndAdd(mn4, u.GetLower(), n2.GetLower());
				mn5 = AdvSimd.MultiplyWideningUpperAndAdd(mn5, u, n2);
				ab6 = AdvSimd.MultiplyWideningLowerAndAdd(ab6, x.GetLower(), b3.GetLower());
				ab7 = AdvSimd.MultiplyWideningUpperAndAdd(ab7, x, b3);
				mn6 = AdvSimd.MultiplyWideningLowerAndAdd(mn6, u.GetLower(), n3.GetLower());
				mn7 = AdvSimd.MultiplyWideningUpperAndAdd(mn7, u, n3);
				b2 = b0;
				b3 = b1;
				n2 = n0;
				n3 = n1;
				b0 = Load(ref b, i + offset + 2);
				b1 = Load(ref b, i + offset + 1);
				n0 = Load(ref n, i + offset + 2);
				n1 = Load(ref n, i + offset + 1);
			}

			if (k < digits)
			{
				for (int j = 0; j < 2; ++j, i += 2)
				{
					Vector128<uint> x = Vector128.LoadUnsafe(ref a, (nuint)(2 * i));
					ab0 = AdvSimd.MultiplyWideningLowerAndAdd(ab0, x.GetLower(), b0.GetLower());
					ab1 = AdvSimd.MultiplyWideningUpperAndAdd(ab1, x, b0);
					ab2 = AdvSimd.MultiplyWideningLowerAndAdd(ab2, x.GetLower(), b1.GetLower());
					ab3 = AdvSimd.MultiplyWideningUpperAndAdd(ab3, x, b1);
					ab4 = AdvSimd.MultiplyWideningLowerAndAdd(ab4, x.GetLower(), b2.GetLower());
					ab5 = AdvSimd.MultiplyWideningUpperAndAdd(ab5, x, b2);
					ab6 = AdvSimd.MultiplyWideningLowerAndAdd(ab6, x.GetLower(), b3.GetLower());
					ab7 = AdvSimd.MultiplyWideningUpperAndAdd(ab7, x, b3);
					b2 = b0;
					b3 = b1;
					b0 = Load(ref b, i + offset + 2);
					b1 = Load(ref b, i + offset + 1);
				}
			}

			carry = Tail(ab0 + ab1 + (mn0 + mn1), ab2 + ab3 + (mn2 + mn3), ab4 + ab5 + (mn4 + mn5), ab6 + ab7 + (mn6 + mn7), carry, moduli, ref m, ref output, k, digits, inverse, mask);
		}
	}

	// As MultiplyCore for a·a: below half = k/2, the cross products with the doubled copy and the reductions; at pairs half and half + 1, lane k takes a_half² and lane k + 2 a_(half+1)² from the plain copy, lanes k + 1 and k + 3 the doubled cross products at half, and lane k + 3 also the one at half + 1; then the reductions alone.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void SquareCore(Span<ulong> result, ref uint a, ref uint reversed, ref uint twice, ref uint n, ref uint m, ReadOnlySpan<ulong> moduli, Vector64<uint> inverse, int digits)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		ref ulong output = ref MemoryMarshal.GetReference(result);
		Vector128<ulong> carry = Vector128<ulong>.Zero;

		for (int k = 0; k < 2 * digits; k += 4)
		{
			Vector128<ulong> ab0 = default, ab1 = default, ab2 = default, ab3 = default, ab4 = default, ab5 = default, ab6 = default, ab7 = default;
			Vector128<ulong> mn0 = default, mn1 = default, mn2 = default, mn3 = default, mn4 = default, mn5 = default, mn6 = default, mn7 = default;
			int start = k < digits ? 0 : k - digits + 1 & ~1;
			int both = Math.Min(k, digits + 1 & ~1);
			int half = k >> 1;
			int offset = digits - 1 - k;
			int i = start;
			Vector128<uint> b0 = Load(ref twice, i + offset);
			Vector128<uint> b1 = Load(ref twice, i + offset - 1);
			Vector128<uint> b2 = Load(ref twice, i + offset - 2);
			Vector128<uint> b3 = Load(ref twice, i + offset - 3);
			Vector128<uint> n0 = Load(ref n, i + offset);
			Vector128<uint> n1 = Load(ref n, i + offset - 1);
			Vector128<uint> n2 = Load(ref n, i + offset - 2);
			Vector128<uint> n3 = Load(ref n, i + offset - 3);

			for (; i < half; i += 2)
			{
				Vector128<uint> x = Vector128.LoadUnsafe(ref a, (nuint)(2 * i));
				Vector128<uint> u = Vector128.LoadUnsafe(ref m, (nuint)(2 * i));
				ab0 = AdvSimd.MultiplyWideningLowerAndAdd(ab0, x.GetLower(), b0.GetLower());
				ab1 = AdvSimd.MultiplyWideningUpperAndAdd(ab1, x, b0);
				mn0 = AdvSimd.MultiplyWideningLowerAndAdd(mn0, u.GetLower(), n0.GetLower());
				mn1 = AdvSimd.MultiplyWideningUpperAndAdd(mn1, u, n0);
				ab2 = AdvSimd.MultiplyWideningLowerAndAdd(ab2, x.GetLower(), b1.GetLower());
				ab3 = AdvSimd.MultiplyWideningUpperAndAdd(ab3, x, b1);
				mn2 = AdvSimd.MultiplyWideningLowerAndAdd(mn2, u.GetLower(), n1.GetLower());
				mn3 = AdvSimd.MultiplyWideningUpperAndAdd(mn3, u, n1);
				ab4 = AdvSimd.MultiplyWideningLowerAndAdd(ab4, x.GetLower(), b2.GetLower());
				ab5 = AdvSimd.MultiplyWideningUpperAndAdd(ab5, x, b2);
				mn4 = AdvSimd.MultiplyWideningLowerAndAdd(mn4, u.GetLower(), n2.GetLower());
				mn5 = AdvSimd.MultiplyWideningUpperAndAdd(mn5, u, n2);
				ab6 = AdvSimd.MultiplyWideningLowerAndAdd(ab6, x.GetLower(), b3.GetLower());
				ab7 = AdvSimd.MultiplyWideningUpperAndAdd(ab7, x, b3);
				mn6 = AdvSimd.MultiplyWideningLowerAndAdd(mn6, u.GetLower(), n3.GetLower());
				mn7 = AdvSimd.MultiplyWideningUpperAndAdd(mn7, u, n3);
				b2 = b0;
				b3 = b1;
				n2 = n0;
				n3 = n1;
				b0 = Load(ref twice, i + offset + 2);
				b1 = Load(ref twice, i + offset + 1);
				n0 = Load(ref n, i + offset + 2);
				n1 = Load(ref n, i + offset + 1);
			}

			{
				Vector128<uint> x = Vector128.LoadUnsafe(ref a, (nuint)(2 * half));
				Vector128<uint> plain0 = Load(ref reversed, half + offset);
				Vector128<uint> plain2 = Load(ref reversed, half + offset - 2);
				ab0 = AdvSimd.MultiplyWideningLowerAndAdd(ab0, x.GetLower(), plain0.GetLower());
				ab2 = AdvSimd.MultiplyWideningLowerAndAdd(ab2, x.GetLower(), b1.GetLower());
				ab4 = AdvSimd.MultiplyWideningLowerAndAdd(ab4, x.GetLower(), b2.GetLower());
				ab5 = AdvSimd.MultiplyWideningUpperAndAdd(ab5, x, plain2);
				ab6 = AdvSimd.MultiplyWideningLowerAndAdd(ab6, x.GetLower(), b3.GetLower());
				ab7 = AdvSimd.MultiplyWideningUpperAndAdd(ab7, x, b3);
			}

			for (; i < both; i += 2)
			{
				Vector128<uint> u = Vector128.LoadUnsafe(ref m, (nuint)(2 * i));
				mn0 = AdvSimd.MultiplyWideningLowerAndAdd(mn0, u.GetLower(), n0.GetLower());
				mn1 = AdvSimd.MultiplyWideningUpperAndAdd(mn1, u, n0);
				mn2 = AdvSimd.MultiplyWideningLowerAndAdd(mn2, u.GetLower(), n1.GetLower());
				mn3 = AdvSimd.MultiplyWideningUpperAndAdd(mn3, u, n1);
				mn4 = AdvSimd.MultiplyWideningLowerAndAdd(mn4, u.GetLower(), n2.GetLower());
				mn5 = AdvSimd.MultiplyWideningUpperAndAdd(mn5, u, n2);
				mn6 = AdvSimd.MultiplyWideningLowerAndAdd(mn6, u.GetLower(), n3.GetLower());
				mn7 = AdvSimd.MultiplyWideningUpperAndAdd(mn7, u, n3);
				n2 = n0;
				n3 = n1;
				n0 = Load(ref n, i + offset + 2);
				n1 = Load(ref n, i + offset + 1);
			}

			carry = Tail(ab0 + ab1 + (mn0 + mn1), ab2 + ab3 + (mn2 + mn3), ab4 + ab5 + (mn4 + mn5), ab6 + ab7 + (mn6 + mn7), carry, moduli, ref m, ref output, k, digits, inverse, mask);
		}
	}

	// Columns k to k + 3 from their sums and the carry into column k, both moduli at once, as MontgomeryKernelAdvSimd.Tail does for one: below digitCount each column gains its digit m times n, from digitCount on each is a digit of the result. Returns the carry out of the block.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Tail(Vector128<ulong> s0, Vector128<ulong> s1, Vector128<ulong> s2, Vector128<ulong> s3, Vector128<ulong> carry, ReadOnlySpan<ulong> moduli, ref uint m, ref ulong output, int k, int digits, Vector64<uint> inverse, ulong digitMask)
	{
		s0 += carry;

		if (k + 4 <= digits)
		{
			ref ulong pairs = ref MemoryMarshal.GetReference(moduli);
			Vector64<uint> n0 = AdvSimd.ExtractNarrowingLower(Vector128.LoadUnsafe(ref pairs));
			Vector64<uint> n1 = AdvSimd.ExtractNarrowingLower(Vector128.LoadUnsafe(ref pairs, 2));
			Vector64<uint> n2 = AdvSimd.ExtractNarrowingLower(Vector128.LoadUnsafe(ref pairs, 4));
			Vector64<uint> n3 = AdvSimd.ExtractNarrowingLower(Vector128.LoadUnsafe(ref pairs, 6));
			Vector64<uint> mask = Vector64.Create((uint)digitMask);
			Vector64<uint> q0 = AdvSimd.Multiply(AdvSimd.ExtractNarrowingLower(s0), inverse) & mask;
			s0 = AdvSimd.MultiplyWideningLowerAndAdd(s0, q0, n0);
			s1 = AdvSimd.MultiplyWideningLowerAndAdd(s1, q0, n1);
			s2 = AdvSimd.MultiplyWideningLowerAndAdd(s2, q0, n2);
			s3 = AdvSimd.MultiplyWideningLowerAndAdd(s3, q0, n3);
			s1 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s1, s0);
			Vector64<uint> q1 = AdvSimd.Multiply(AdvSimd.ExtractNarrowingLower(s1), inverse) & mask;
			s1 = AdvSimd.MultiplyWideningLowerAndAdd(s1, q1, n0);
			s2 = AdvSimd.MultiplyWideningLowerAndAdd(s2, q1, n1);
			s3 = AdvSimd.MultiplyWideningLowerAndAdd(s3, q1, n2);
			s2 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s2, s1);
			Vector64<uint> q2 = AdvSimd.Multiply(AdvSimd.ExtractNarrowingLower(s2), inverse) & mask;
			s2 = AdvSimd.MultiplyWideningLowerAndAdd(s2, q2, n0);
			s3 = AdvSimd.MultiplyWideningLowerAndAdd(s3, q2, n1);
			s3 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s3, s2);
			Vector64<uint> q3 = AdvSimd.Multiply(AdvSimd.ExtractNarrowingLower(s3), inverse) & mask;
			s3 = AdvSimd.MultiplyWideningLowerAndAdd(s3, q3, n0);
			Vector128.Create(q0, q1).StoreUnsafe(ref m, (nuint)(2 * k));
			Vector128.Create(q2, q3).StoreUnsafe(ref m, (nuint)(2 * k + 4));
			return MontgomeryKernelAdvSimd<TRadix>.ShiftRight(s3);
		}

		if (k >= digits)
		{
			Vector128<ulong> mask = Vector128.Create(digitMask);
			s1 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s1, s0);
			s2 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s2, s1);
			s3 = MontgomeryKernelAdvSimd<TRadix>.ShiftRightAdd(s3, s2);
			int index = k - digits;
			(s0 & mask).StoreUnsafe(ref output, (nuint)(2 * index));

			// The last block, of 1, 2 or 3 columns.
			if (index + 1 < digits)
			{
				(s1 & mask).StoreUnsafe(ref output, (nuint)(2 * index + 2));
			}

			if (index + 2 < digits)
			{
				(s2 & mask).StoreUnsafe(ref output, (nuint)(2 * index + 4));
			}

			if (index + 3 < digits)
			{
				(s3 & mask).StoreUnsafe(ref output, (nuint)(2 * index + 6));
			}

			return MontgomeryKernelAdvSimd<TRadix>.ShiftRight(s3);
		}

		return Straddle(s0, s1, s2, s3, moduli, ref m, ref output, k, digits, inverse);
	}

	// The block across digitCount, column by column on each lane.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static Vector128<ulong> Straddle(Vector128<ulong> s0, Vector128<ulong> s1, Vector128<ulong> s2, Vector128<ulong> s3, ReadOnlySpan<ulong> moduli, ref uint m, ref ulong output, int k, int digits, Vector64<uint> inverse)
	{
		int bits = TRadix.Bits;
		ulong mask = (1UL << bits) - 1;
		Span<ulong> sums = [s0.ToScalar(), s1.ToScalar(), s2.ToScalar(), s3.ToScalar(), s0.GetElement(1), s1.GetElement(1), s2.GetElement(1), s3.GetElement(1)];
		ulong firstCarry = 0;
		ulong secondCarry = 0;

		for (int lane = 0; lane < 2; ++lane)
		{
			uint negativeInverse = inverse.GetElement(lane);
			ulong carry = 0;

			for (int j = 0; j < 4; ++j)
			{
				int c = k + j;
				ulong sum = sums[4 * lane + j] + carry;

				if (c < digits)
				{
					uint digit = (uint)sum * negativeInverse & (uint)mask;
					Unsafe.Add(ref m, 2 * c + lane) = digit;
					sum += digit * moduli[lane];

					for (int t = j + 1; t < 4; ++t)
					{
						sums[4 * lane + t] += digit * moduli[2 * (t - j) + lane];
					}
				}
				else if (c - digits < digits)
				{
					Unsafe.Add(ref output, 2 * (c - digits) + lane) = sum & mask;
				}

				carry = sum >> bits;
			}

			if (lane is 0)
			{
				firstCarry = carry;
			}
			else
			{
				secondCarry = carry;
			}
		}

		// Erased, as the scratch is.
		sums.ZeroMemory();
		return Vector128.Create(firstCarry, secondCarry);
	}
}
