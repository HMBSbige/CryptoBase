namespace CryptoBase.EllipticCurves.Curve448;

// The block products of Field448x4Avx2 and of each pair of Field448x4Sse41, on vectors TVector of their limbs with the arithmetic of TOps.
internal static class Field448Blocks<TVector, TOps> where TVector : unmanaged where TOps : struct, IField448Vector<TVector>
{
	internal const int Bits = 28;
	internal const ulong Mask = (1UL << Bits) - 1;

	// The limbs of 2p, each at least the largest limb of a reduced value; limb 8 is the smaller.
	internal const ulong TwoP = (1UL << 29) - 2;
	internal const ulong TwoP8 = (1UL << 29) - 4;

	// The operands of Product in its scratch, in vectors: the left one at Left, the sums of its halves at Sums and the right one, as Product takes it, at Right.
	internal const int Left = 0;
	internal const int Sums = 16;
	internal const int Right = 24;

	// The lane products by golden-ratio Karatsuba: with x = x_lo + φ·x_hi and y likewise, x·y ≡ x_lo·y_lo + x_hi·y_hi + φ·((x_lo + x_hi)·(y_lo + y_hi) − x_lo·y_lo). Taken limb by limb, column j of each half sums, for k from 0 to 7, the product of x_k = (x_lo,k, x_hi,k) and y_n = (low_n, high_n) for n = j − k + 8 (see PrepareRight), which is y_(j−k) where k ≤ j and φ·y_(j−k+8) where k > j, as φ moves a product of weight φ² down to φ and 1: with P = x_lo,k·low_n, Q = x_hi,k·high_n and R = (x_lo,k + x_hi,k)·sum_n, column j of x_lo takes P + Q and column j of x_hi takes R − P.
	// R − P is x_lo·high + x_hi·low + x_hi·high, at most 3·m_x·m_y·2^56 for y_(j−k) and 5·m_x·m_y·2^56 for φ·y, whose high is y_lo + y_hi; P + Q is at most 2 and 3 times that. Column j of x_hi thus stays below (38 − 2j)·m_x·m_y·2^56 and column j of x_lo below (23 − j)·m_x·m_y·2^56, which with the carry, below 2^36, stay below 2^64 for m_x·m_y ≤ 6.7; the sums take x_lo + x_hi < 2^32 and low + 2·high < 2^32 to the multiplier. P, Q and R add up separately, modulo 2^64 like the result.
	// The columns go four at a time, each block taking x_k into registers once for each k and the operands of y from memory, with a chain of carries from column 0 of each half to column 7 that the next block continues; the carry out of the top of x_lo goes into limb 8, and the one out of the top of x_hi, of weight φ², into limbs 0 and 8, after which limbs 0 and 8 carry once more into limbs 1 and 9.
	// Inlined into the steps of Field448x4Avx2, so that the callee-saved vector registers of the Windows ABI, all of which the product needs without AVX-512, are saved once per step rather than once per product.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Product(ref TVector operands, ref TVector result)
	{
		ref TVector right = ref Unsafe.Add(ref operands, Right);
		TVector carryLow = default;
		TVector carryHigh = default;

		for (nint j = 0; j < 8; j += 4)
		{
			TVector p0 = default, q0 = default, r0 = default;
			TVector p1 = default, q1 = default, r1 = default;
			TVector p2 = default, q2 = default, r2 = default;
			TVector p3 = default, q3 = default, r3 = default;
			ref TVector x = ref Unsafe.Add(ref operands, Left);

			// y_n for n = j + c − k + 8 lies at index c of y.
			ref TVector y = ref Unsafe.Add(ref right, j + 8);

			for (nint k = 0; k < 8; ++k)
			{
				TVector low = x;
				TVector high = Unsafe.Add(ref x, 8);
				TVector sum = Unsafe.Add(ref x, 16);
				Accumulate(ref y, 0, low, high, sum, ref p0, ref q0, ref r0);
				Accumulate(ref y, 1, low, high, sum, ref p1, ref q1, ref r1);
				Accumulate(ref y, 2, low, high, sum, ref p2, ref q2, ref r2);
				Accumulate(ref y, 3, low, high, sum, ref p3, ref q3, ref r3);
				x = ref Unsafe.Add(ref x, 1);
				y = ref Unsafe.Subtract(ref y, 1);
			}

			Column(ref result, j, p0, q0, r0, ref carryLow, ref carryHigh);
			Column(ref result, j + 1, p1, q1, r1, ref carryLow, ref carryHigh);
			Column(ref result, j + 2, p2, q2, r2, ref carryLow, ref carryHigh);
			Column(ref result, j + 3, p3, q3, r3, ref carryLow, ref carryHigh);
		}

		Wrap(ref result, carryLow, carryHigh);
	}

	// x_k times sum_n, high_n and low_n at index c of y.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Accumulate(ref TVector y, nint c, TVector low, TVector high, TVector sum, ref TVector p, ref TVector q, ref TVector r)
	{
		p = TOps.MultiplyAdd(p, low, Unsafe.Add(ref y, c + 16));
		q = TOps.MultiplyAdd(q, high, Unsafe.Add(ref y, c + 8));
		r = TOps.MultiplyAdd(r, sum, Unsafe.Add(ref y, c));
	}

	// Columns j and j + 8 from their sums of P, Q and R and the carries into them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Column(ref TVector result, nint j, TVector p, TVector q, TVector r, ref TVector carryLow, ref TVector carryHigh)
	{
		TVector mask = TOps.Create(Mask);
		TVector low = TOps.Add(TOps.Add(p, q), carryLow);
		TVector high = TOps.Add(TOps.Subtract(r, p), carryHigh);
		Unsafe.Add(ref result, j) = TOps.And(low, mask);
		Unsafe.Add(ref result, j + 8) = TOps.And(high, mask);
		carryLow = TOps.ShiftRight(low, Bits);
		carryHigh = TOps.ShiftRight(high, Bits);
	}

	// The carry out of limb 7 into limb 8 and the one out of limb 15, of weight 2^448 ≡ φ + 1, into limbs 0 and 8, each below 2^36, then one carry out of limbs 0 and 8, below 2^8 + 1 and 2^9 + 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Wrap(ref TVector limbs, TVector carryLow, TVector carryHigh)
	{
		TVector mask = TOps.Create(Mask);
		TVector low = TOps.Add(limbs, carryHigh);
		TVector high = TOps.Add(TOps.Add(Unsafe.Add(ref limbs, 8), carryLow), carryHigh);
		limbs = TOps.And(low, mask);
		ref TVector limb1 = ref Unsafe.Add(ref limbs, 1);
		limb1 = TOps.Add(limb1, TOps.ShiftRight(low, Bits));
		Unsafe.Add(ref limbs, 8) = TOps.And(high, mask);
		ref TVector limb9 = ref Unsafe.Add(ref limbs, 9);
		limb9 = TOps.Add(limb9, TOps.ShiftRight(high, Bits));
	}

	// The square of the left operand by Product's golden-ratio Karatsuba: column j sums x_k·y_n over k with n = j − k + 8, and as y_n is x_(n − 8) for n ≥ 8 and φ·x_n below, the terms of k and n − 8, or of k and n, are equal. Each pair takes one lane product of the doubled operand, and the term where they meet, for even j, one of the operand: 36 lane products where Product takes 64. Each column sums what Product's does, within its bounds; the doubled operand stays below 2^32 for m ≤ 4.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void SquareProduct(ref TVector operands, ref TVector doubled, ref TVector result)
	{
		ref TVector x = ref Unsafe.Add(ref operands, Left);
		ref TVector d = ref doubled;
		ref TVector y = ref Unsafe.Add(ref operands, Right);
		TVector carryLow = default;
		TVector carryHigh = default;
		TVector p0 = default, q0 = default, r0 = default;
		TVector p1 = default, q1 = default, r1 = default;

		// Two columns at a time, the terms of each k together, so that the values that a term loads are not held across many others.
		Term(ref x, 0, ref y, 8, ref p0, ref q0, ref r0);
		Term(ref d, 0, ref y, 9, ref p1, ref q1, ref r1);
		Term(ref d, 1, ref y, 7, ref p0, ref q0, ref r0);
		Term(ref d, 2, ref y, 6, ref p0, ref q0, ref r0);
		Term(ref d, 2, ref y, 7, ref p1, ref q1, ref r1);
		Term(ref d, 3, ref y, 5, ref p0, ref q0, ref r0);
		Term(ref d, 3, ref y, 6, ref p1, ref q1, ref r1);
		Term(ref x, 4, ref y, 4, ref p0, ref q0, ref r0);
		Term(ref d, 4, ref y, 5, ref p1, ref q1, ref r1);
		Column(ref result, 0, p0, q0, r0, ref carryLow, ref carryHigh);
		Column(ref result, 1, p1, q1, r1, ref carryLow, ref carryHigh);
		p0 = default;
		q0 = default;
		r0 = default;
		p1 = default;
		q1 = default;
		r1 = default;
		Term(ref d, 0, ref y, 10, ref p0, ref q0, ref r0);
		Term(ref d, 0, ref y, 11, ref p1, ref q1, ref r1);
		Term(ref x, 1, ref y, 9, ref p0, ref q0, ref r0);
		Term(ref d, 1, ref y, 10, ref p1, ref q1, ref r1);
		Term(ref d, 3, ref y, 7, ref p0, ref q0, ref r0);
		Term(ref d, 4, ref y, 6, ref p0, ref q0, ref r0);
		Term(ref d, 4, ref y, 7, ref p1, ref q1, ref r1);
		Term(ref x, 5, ref y, 5, ref p0, ref q0, ref r0);
		Term(ref d, 5, ref y, 6, ref p1, ref q1, ref r1);
		Column(ref result, 2, p0, q0, r0, ref carryLow, ref carryHigh);
		Column(ref result, 3, p1, q1, r1, ref carryLow, ref carryHigh);
		p0 = default;
		q0 = default;
		r0 = default;
		p1 = default;
		q1 = default;
		r1 = default;
		Term(ref d, 0, ref y, 12, ref p0, ref q0, ref r0);
		Term(ref d, 0, ref y, 13, ref p1, ref q1, ref r1);
		Term(ref d, 1, ref y, 11, ref p0, ref q0, ref r0);
		Term(ref d, 1, ref y, 12, ref p1, ref q1, ref r1);
		Term(ref x, 2, ref y, 10, ref p0, ref q0, ref r0);
		Term(ref d, 2, ref y, 11, ref p1, ref q1, ref r1);
		Term(ref d, 5, ref y, 7, ref p0, ref q0, ref r0);
		Term(ref x, 6, ref y, 6, ref p0, ref q0, ref r0);
		Term(ref d, 6, ref y, 7, ref p1, ref q1, ref r1);
		Column(ref result, 4, p0, q0, r0, ref carryLow, ref carryHigh);
		Column(ref result, 5, p1, q1, r1, ref carryLow, ref carryHigh);
		p0 = default;
		q0 = default;
		r0 = default;
		p1 = default;
		q1 = default;
		r1 = default;
		Term(ref d, 0, ref y, 14, ref p0, ref q0, ref r0);
		Term(ref d, 0, ref y, 15, ref p1, ref q1, ref r1);
		Term(ref d, 1, ref y, 13, ref p0, ref q0, ref r0);
		Term(ref d, 1, ref y, 14, ref p1, ref q1, ref r1);
		Term(ref d, 2, ref y, 12, ref p0, ref q0, ref r0);
		Term(ref d, 2, ref y, 13, ref p1, ref q1, ref r1);
		Term(ref x, 3, ref y, 11, ref p0, ref q0, ref r0);
		Term(ref d, 3, ref y, 12, ref p1, ref q1, ref r1);
		Term(ref x, 7, ref y, 7, ref p0, ref q0, ref r0);
		Column(ref result, 6, p0, q0, r0, ref carryLow, ref carryHigh);
		Column(ref result, 7, p1, q1, r1, ref carryLow, ref carryHigh);
		Wrap(ref result, carryLow, carryHigh);
	}

	// x_k, of the operand or of its double, times sum_n, high_n and low_n of the right operand.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Term(ref TVector x, nint k, ref TVector y, nint n, ref TVector p, ref TVector q, ref TVector r)
	{
		p = TOps.MultiplyAdd(p, Unsafe.Add(ref x, k), Unsafe.Add(ref y, n + 16));
		q = TOps.MultiplyAdd(q, Unsafe.Add(ref x, k + 8), Unsafe.Add(ref y, n + 8));
		r = TOps.MultiplyAdd(r, Unsafe.Add(ref x, k + 16), Unsafe.Add(ref y, n));
	}

	// One carry from each limb of the left operand into the next, from the values before it, with the one out of limb 15 into limbs 0 and 8, then the sums of its halves.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void CarryLeft(ref TVector operands)
	{
		TVector mask = TOps.Create(Mask);
		ref TVector left = ref Unsafe.Add(ref operands, Left);
		TVector carryLow = TOps.ShiftRight(Unsafe.Add(ref left, 15), Bits);
		TVector carryHigh = TOps.Add(TOps.ShiftRight(Unsafe.Add(ref left, 7), Bits), carryLow);

		for (nint i = 0; i < 8; ++i)
		{
			TVector low = Unsafe.Add(ref left, i);
			TVector high = Unsafe.Add(ref left, i + 8);
			TVector carriedLow = TOps.Add(TOps.And(low, mask), carryLow);
			TVector carriedHigh = TOps.Add(TOps.And(high, mask), carryHigh);
			Unsafe.Add(ref left, i) = carriedLow;
			Unsafe.Add(ref left, i + 8) = carriedHigh;
			Unsafe.Add(ref operands, Sums + i) = TOps.Add(carriedLow, carriedHigh);
			carryLow = TOps.ShiftRight(low, Bits);
			carryHigh = TOps.ShiftRight(high, Bits);
		}
	}

	// Writes limbs i and i + 8 of y in the form that Product takes: (low_n, high_n) for n ≥ 8 is y_(n−8) = y_lo,(n−8) + φ·y_hi,(n−8), and for n < 8 it is φ·y_n = y_hi,n + φ·(y_lo,n + y_hi,n), as φ² ≡ φ + 1; sum_n = low_n + high_n. As high_n is sum_(n+8) and low_n is high_(n+8) for n < 8, the 32 vectors at Right, sum_0 to sum_7, then sum_8 to sum_15, then high_8 to high_15, then low_8 to low_15, hold sum_n at n, high_n at n + 8 and low_n at n + 16; sum_0 goes unused.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void PrepareRight(ref TVector operands, nint i, TVector low, TVector high)
	{
		ref TVector right = ref Unsafe.Add(ref operands, Right);
		TVector sum = TOps.Add(low, high);
		Unsafe.Add(ref right, i) = TOps.Add(sum, high);
		Unsafe.Add(ref right, 8 + i) = sum;
		Unsafe.Add(ref right, 16 + i) = high;
		Unsafe.Add(ref right, 24 + i) = low;
	}

	// Limbs i and i + 8 of the left operand, the sum of its halves, and those of the right one as PrepareRight writes them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void WriteOperands(ref TVector operands, nint i, TVector leftLow, TVector leftHigh, TVector rightLow, TVector rightHigh)
	{
		Unsafe.Add(ref operands, Left + i) = leftLow;
		Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
		Unsafe.Add(ref operands, Sums + i) = TOps.Add(leftLow, leftHigh);
		PrepareRight(ref operands, i, rightLow, rightHigh);
	}

	// Limbs i, i + 1, i + 8 and i + 9 of the left operand and the sums of its halves from a 56-bit limb of the low half and the one of the high half, each lane where negate is set taken from 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void WriteEntryLimbs(ref TVector operands, nint i, TVector low, TVector high, TVector negate)
	{
		TVector mask = TOps.Create(Mask);
		TVector twoP = TOps.Create(TwoP);
		TVector limb0 = NegateUnder(TOps.And(low, mask), twoP, negate);
		TVector limb1 = NegateUnder(TOps.ShiftRight(low, Bits), twoP, negate);
		TVector limb8 = NegateUnder(TOps.And(high, mask), TOps.Create(i is 0 ? TwoP8 : TwoP), negate);
		TVector limb9 = NegateUnder(TOps.ShiftRight(high, Bits), twoP, negate);
		ref TVector left = ref Unsafe.Add(ref operands, Left + i);
		left = limb0;
		Unsafe.Add(ref left, 1) = limb1;
		Unsafe.Add(ref left, 8) = limb8;
		Unsafe.Add(ref left, 9) = limb9;
		ref TVector sums = ref Unsafe.Add(ref operands, Sums + i);
		sums = TOps.Add(limb0, limb8);
		Unsafe.Add(ref sums, 1) = TOps.Add(limb1, limb9);
	}

	// value, or 2p − value where negate is set: (value ^ m) + (m & (2p + 1)) is 2p − value modulo 2^64 for m all ones.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector NegateUnder(TVector value, TVector twoP, TVector negate)
	{
		return TOps.Add(TOps.Xor(value, negate), TOps.And(negate, TOps.Add(twoP, TOps.Create(1))));
	}
}
