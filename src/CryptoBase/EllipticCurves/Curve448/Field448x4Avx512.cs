namespace CryptoBase.EllipticCurves.Curve448;

// The limbs of Field448x4Avx2 two to a 512-bit vector: vector k holds limb k of lanes A, B, C, D in its low half and limb k + 8 of the same lanes in its high half, the halves x_lo,k and x_hi,k of x = x_lo + φ·x_hi, so that each lane of a half is a lane of Field448x4Avx2 and the four-lane formulas run on both halves at once. The members take and give the bounds of Field448x4Avx2.
internal partial struct Field448x4Avx512
{
	internal Vector512<ulong> L0;
	internal Vector512<ulong> L1;
	internal Vector512<ulong> L2;
	internal Vector512<ulong> L3;
	internal Vector512<ulong> L4;
	internal Vector512<ulong> L5;
	internal Vector512<ulong> L6;
	internal Vector512<ulong> L7;

	private const int Bits = 28;
	private const ulong Mask = (1UL << Bits) - 1;

	private const ulong TwoP = (1UL << 29) - 2;
	private const ulong TwoP8 = (1UL << 29) - 4;
	private const ulong EightP = (1UL << 31) - 8;
	private const ulong EightP8 = (1UL << 31) - 16;

	private const ulong SixteenA24 = 16 * 39081;

	// The operands of Product in its scratch, in vectors: the left one at Left and the sums of its halves, paired, at Sums; the right one at Right + 7 to Right + 14, after φ times its vectors 1 to 7, and the sums of the halves of those fifteen, paired, at Pairs; a step keeps its products at Products.
	private const int Left = 0;
	private const int Sums = 8;
	private const int Right = 12;
	private const int Pairs = 27;
	private const int Products = 41;

	// The lanes of each half, as bits of LaneMask.
	private const byte LaneB = 0b0010;
	private const byte LaneC = 0b0100;
	private const byte LaneD = 0b1000;

	// vpermq controls within each half, named by the lanes they take.
	private const byte Abdc = 0b10_11_01_00;
	private const byte Aaab = 0b01_00_00_00;
	private const byte Cdab = 0b01_00_11_10;

	// vpshufd control that swaps the 64-bit lanes of each 128-bit quarter: (B, A, D, C) in each half.
	private const byte Badc = 0b01_00_11_10;

	// vshufi64x2 controls: the low halves of two vectors, their high halves, the low half of the first with the high half of the second, and the halves of one swapped.
	private const byte LowHalves = 0b01_00_01_00;
	private const byte HighHalves = 0b11_10_11_10;
	private const byte LowHigh = 0b11_10_01_00;
	private const byte SwapHalves = 0b01_00_11_10;

	// The vpternlogq table of A ? B : C.
	private const byte Select = 0xCA;

	public static bool IsSupported => Avx512F.IsSupported && Vector512.IsHardwareAccelerated;

	// As Field448x4Avx2.Create: the 56-bit limbs m and m + 4 make vectors 2m and 2m + 1.
	public static void Create(in Field448 a, in Field448 b, in Field448 c, in Field448 d, out Field448x4Avx512 result)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		Vector512<ulong> w0 = Vector512.Create(a.L0, b.L0, c.L0, d.L0, a.L4, b.L4, c.L4, d.L4);
		Vector512<ulong> w1 = Vector512.Create(a.L1, b.L1, c.L1, d.L1, a.L5, b.L5, c.L5, d.L5);
		Vector512<ulong> w2 = Vector512.Create(a.L2, b.L2, c.L2, d.L2, a.L6, b.L6, c.L6, d.L6);
		Vector512<ulong> w3 = Vector512.Create(a.L3, b.L3, c.L3, d.L3, a.L7, b.L7, c.L7, d.L7);
		result.L0 = (w0 & mask) + IntoLimbZero(w3 >> 2 * Bits);
		result.L1 = w0 >> Bits & mask;
		result.L2 = (w1 & mask) + (w0 >> 2 * Bits);
		result.L3 = w1 >> Bits & mask;
		result.L4 = (w2 & mask) + (w1 >> 2 * Bits);
		result.L5 = w2 >> Bits & mask;
		result.L6 = (w3 & mask) + (w2 >> 2 * Bits);
		result.L7 = w3 >> Bits & mask;
	}

	public static void Extract(in Field448x4Avx512 value, out Field448 a, out Field448 b, out Field448 c, out Field448 d)
	{
		ReadOnlySpan<Vector512<ulong>> limbs = MemoryMarshal.CreateReadOnlySpan(in value.L0, 8);
		Join(limbs, 0, out a);
		Join(limbs, 1, out b);
		Join(limbs, 2, out c);
		Join(limbs, 3, out d);
	}

	// As Field448x4Avx2.Join.
	private static void Join(ReadOnlySpan<Vector512<ulong>> limbs, int lane, out Field448 result)
	{
		Span<ulong> carried = stackalloc ulong[16];
		ulong carry = 0;

		for (int i = 0; i < carried.Length; ++i)
		{
			ulong sum = limbs[i & 7].GetElement(lane + (i >> 3 << 2)) + carry;
			carried[i] = sum & Mask;
			carry = sum >> Bits;
		}

		carried[0] += carry;
		carried[8] += carry;
		result.L0 = carried[0] + (carried[1] << Bits);
		result.L1 = carried[2] + (carried[3] << Bits);
		result.L2 = carried[4] + (carried[5] << Bits);
		result.L3 = carried[6] + (carried[7] << Bits);
		result.L4 = carried[8] + (carried[9] << Bits);
		result.L5 = carried[10] + (carried[11] << Bits);
		result.L6 = carried[12] + (carried[13] << Bits);
		result.L7 = carried[14] + (carried[15] << Bits);
		carried.ZeroMemory();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field448x4Avx512 value)
	{
		Vector512<ulong> select = Vector512.Create(mask);
		ref Vector512<ulong> limbs = ref value.L0;

		for (nint k = 0; k < 8; ++k)
		{
			ref Vector512<ulong> limb = ref Unsafe.Add(ref limbs, k);
			limb = Vector512.ConditionalSelect(select, Avx512F.Permute4x64(limb, Cdab), limb);
		}
	}

	// The factors of Field448x4Avx2.CreateMultiplier, eight columns to a vector: vector i holds those of limb i for columns 0 to 7 and vector 16 + i those for columns 8 to 15.
	public static int MultiplierLength => 4;

	public static void CreateMultiplier(in Field448 u, Span<Field448x4Avx512> multiplier)
	{
		Debug.Assert(multiplier.Length is 4);

		Create(in u, in u, in u, in u, out Field448x4Avx512 limbs);
		ReadOnlySpan<Vector512<ulong>> uLimbs = MemoryMarshal.CreateReadOnlySpan(ref limbs.L0, 8);
		Span<ulong> factors = MemoryMarshal.Cast<Field448x4Avx512, ulong>(multiplier);
		factors.Clear();

		for (int i = 0; i < 16; ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				ulong term = uLimbs[j & 7].GetElement(j >> 3 << 2);
				int s = i + j;

				if (s < 16)
				{
					AddFactor(factors, i, s, term);
				}
				else if (s < 24)
				{
					AddFactor(factors, i, s - 8, term);
					AddFactor(factors, i, s - 16, term);
				}
				else
				{
					AddFactor(factors, i, s - 16, 2 * term);
					AddFactor(factors, i, s - 24, term);
				}
			}
		}

		limbs.ZeroMemory();
	}

	private static void AddFactor(Span<ulong> factors, int limb, int column, ulong term)
	{
		factors[(column >> 3) * 128 + limb * 8 + (column & 7)] += term;
	}

	// The operands and the products of a step in seven values.
	public static int ScratchLength => 7;

	// The products and operands of Field448x4Avx2.LadderStep.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderStep(ref Field448x4Avx512 state, ulong swap, in Field448x4Avx512 multiplier, ref Field448x4Avx512 scratch)
	{
		ref Vector512<ulong> operands = ref scratch.L0;
		ref Vector512<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareLadder(in state, swap, ref operands);
		Product(ref operands, ref products);
		FinishLadder(ref products, ref operands);
		Product(ref operands, ref products);
		MultiplyLaneD(ref products, in multiplier, ref state);
	}

	// The operands of the first product, as Field448x4Avx2.PrepareLadder takes them, with the swap of the lanes of each half by the index of a vpermq.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(in Field448x4Avx512 state, ulong swap, ref Vector512<ulong> operands)
	{
		Vector512<ulong> flip = Vector512.Create(swap & 2);
		Vector512<ulong> xs = Vector512.Create(0UL, 0, 2, 2, 4, 4, 6, 6) ^ flip;
		Vector512<ulong> zs = Vector512.Create(1UL, 1, 3, 3, 5, 5, 7, 7) ^ flip;
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		PrepareLadder(state.L0, xs, zs, Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8), out Vector512<ulong> left0, out Vector512<ulong> right0);
		PrepareLadder(state.L1, xs, zs, twoP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		PrepareLadder(state.L2, xs, zs, twoP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		PrepareLadder(state.L3, xs, zs, twoP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		PrepareLadder(state.L4, xs, zs, twoP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		PrepareLadder(state.L5, xs, zs, twoP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		PrepareLadder(state.L6, xs, zs, twoP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		PrepareLadder(state.L7, xs, zs, twoP, out Vector512<ulong> left7, out Vector512<ulong> right7);
		WriteLeft(ref operands, left0, left1, left2, left3, left4, left5, left6, left7);
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
	}

	// (x2, x2, x3, x3) + (z2, 2p − z2, z3, 2p − z3) = (A, B, C, D) in each half, then (A, x2, D, C) and (A, z2, A, B).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(Vector512<ulong> limb, Vector512<ulong> xs, Vector512<ulong> zs, Vector512<ulong> twoP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> laneB = LaneMask(LaneB);
		Vector512<ulong> x = Avx512F.PermuteVar8x64(limb, xs);
		Vector512<ulong> z = Avx512F.PermuteVar8x64(limb, zs);
		Vector512<ulong> sums = x + Blend(z, twoP - z, LaneMask(LaneB | LaneD));
		left = Blend(Avx512F.Permute4x64(sums, Abdc), x, laneB);
		right = Blend(Avx512F.Permute4x64(sums, Aaab), z, laneB);
	}

	// The operands of the second product, as Field448x4Avx2.FinishLadder takes them, the carry into the vector of limbs 0 and 8 coming from the top of each half of the vector of limbs 7 and 15.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(ref Vector512<ulong> products, ref Vector512<ulong> operands)
	{
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		Vector512<ulong> eightP = Vector512.Create(EightP);
		FinishLadder(products, Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8), Vector512.Create(EightP, EightP, EightP, EightP, EightP8, EightP8, EightP8, EightP8), out Vector512<ulong> left0, out Vector512<ulong> right0);
		FinishLadder(Unsafe.Add(ref products, 1), twoP, eightP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		FinishLadder(Unsafe.Add(ref products, 2), twoP, eightP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		FinishLadder(Unsafe.Add(ref products, 3), twoP, eightP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		FinishLadder(Unsafe.Add(ref products, 4), twoP, eightP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		FinishLadder(Unsafe.Add(ref products, 5), twoP, eightP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		FinishLadder(Unsafe.Add(ref products, 6), twoP, eightP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		FinishLadder(Unsafe.Add(ref products, 7), twoP, eightP, out Vector512<ulong> left7, out Vector512<ulong> right7);

		// One carry from each limb into the next, from the values before it.
		Vector512<ulong> mask = Vector512.Create(Mask);
		WriteLeft(ref operands, (left0 & mask) + IntoLimbZero(left7 >> Bits), (left1 & mask) + (left0 >> Bits), (left2 & mask) + (left1 >> Bits), (left3 & mask) + (left2 >> Bits), (left4 & mask) + (left3 >> Bits), (left5 & mask) + (left4 >> Bits), (left6 & mask) + (left5 >> Bits), (left7 & mask) + (left6 >> Bits));
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
	}

	// (AA, w, DA, CB) and its swap (w, AA, CB, DA) in each half to the lanes of the operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector512<ulong> limb, Vector512<ulong> twoP, Vector512<ulong> eightP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> tail = LaneMask(LaneC | LaneD);
		Vector512<ulong> swapped = Avx512F.Shuffle(limb.AsUInt32(), Badc).AsUInt64();
		Vector512<ulong> four = swapped << 2;
		Vector512<ulong> lanes = Blend(limb + swapped, swapped + twoP - limb, LaneMask(LaneD));
		left = Blend(Blend(limb + eightP - four, four + M(limb, Vector512.Create(0, SixteenA24, 0, 0, 0, SixteenA24, 0, 0)), LaneMask(LaneB)), lanes, tail);
		right = Blend(limb, lanes, tail);
	}

	// Each half of carry, from the top limb of a half, into limbs 0 and 8: the low half, of weight φ, into limb 8, and the high half, of weight φ² ≡ φ + 1, into both.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> IntoLimbZero(Vector512<ulong> carry)
	{
		return Avx512F.Shuffle4x128(carry, carry, SwapHalves) + (carry & HighHalf());
	}

	// The left operand and the sums of its halves, paired: vector m of Sums holds those of vectors 2m and 2m + 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteLeft(ref Vector512<ulong> operands, Vector512<ulong> x0, Vector512<ulong> x1, Vector512<ulong> x2, Vector512<ulong> x3, Vector512<ulong> x4, Vector512<ulong> x5, Vector512<ulong> x6, Vector512<ulong> x7)
	{
		ref Vector512<ulong> x = ref Unsafe.Add(ref operands, Left);
		x = x0;
		Unsafe.Add(ref x, 1) = x1;
		Unsafe.Add(ref x, 2) = x2;
		Unsafe.Add(ref x, 3) = x3;
		Unsafe.Add(ref x, 4) = x4;
		Unsafe.Add(ref x, 5) = x5;
		Unsafe.Add(ref x, 6) = x6;
		Unsafe.Add(ref x, 7) = x7;
		ref Vector512<ulong> sums = ref Unsafe.Add(ref operands, Sums);
		sums = SumPair(x0, x1);
		Unsafe.Add(ref sums, 1) = SumPair(x2, x3);
		Unsafe.Add(ref sums, 2) = SumPair(x4, x5);
		Unsafe.Add(ref sums, 3) = SumPair(x6, x7);
	}

	// The sums of the halves of even and of odd.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> SumPair(Vector512<ulong> even, Vector512<ulong> odd)
	{
		return Avx512F.Shuffle4x128(even, odd, LowHalves) + Avx512F.Shuffle4x128(even, odd, HighHalves);
	}

	// The right operand y, after φ times its vectors 1 to 7, (y_hi, y_lo + y_hi), and the pairs of sums of the halves of the fifteen: vector q − 2 of Pairs holds sum_q and sum_(q−1), where sum_n is low_n + high_n of the right operand y_n of Field448x4Avx2.Product. g_k holds (sum_(k+8), sum_k), the sums of y_k and of φ·y_k.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteRight(ref Vector512<ulong> operands, Vector512<ulong> y0, Vector512<ulong> y1, Vector512<ulong> y2, Vector512<ulong> y3, Vector512<ulong> y4, Vector512<ulong> y5, Vector512<ulong> y6, Vector512<ulong> y7)
	{
		ref Vector512<ulong> right = ref Unsafe.Add(ref operands, Right);
		Vector512<ulong> g0 = Twist(y0) + y0;
		Vector512<ulong> g1 = Twist(ref right, 0, y1);
		Vector512<ulong> g2 = Twist(ref right, 1, y2);
		Vector512<ulong> g3 = Twist(ref right, 2, y3);
		Vector512<ulong> g4 = Twist(ref right, 3, y4);
		Vector512<ulong> g5 = Twist(ref right, 4, y5);
		Vector512<ulong> g6 = Twist(ref right, 5, y6);
		Vector512<ulong> g7 = Twist(ref right, 6, y7);
		Unsafe.Add(ref right, 7) = y0;
		Unsafe.Add(ref right, 8) = y1;
		Unsafe.Add(ref right, 9) = y2;
		Unsafe.Add(ref right, 10) = y3;
		Unsafe.Add(ref right, 11) = y4;
		Unsafe.Add(ref right, 12) = y5;
		Unsafe.Add(ref right, 13) = y6;
		Unsafe.Add(ref right, 14) = y7;
		ref Vector512<ulong> pairs = ref Unsafe.Add(ref operands, Pairs);
		pairs = Avx512F.Shuffle4x128(g2, g1, HighHalves);
		Unsafe.Add(ref pairs, 1) = Avx512F.Shuffle4x128(g3, g2, HighHalves);
		Unsafe.Add(ref pairs, 2) = Avx512F.Shuffle4x128(g4, g3, HighHalves);
		Unsafe.Add(ref pairs, 3) = Avx512F.Shuffle4x128(g5, g4, HighHalves);
		Unsafe.Add(ref pairs, 4) = Avx512F.Shuffle4x128(g6, g5, HighHalves);
		Unsafe.Add(ref pairs, 5) = Avx512F.Shuffle4x128(g7, g6, HighHalves);
		Unsafe.Add(ref pairs, 6) = Avx512F.Shuffle4x128(g0, g7, LowHigh);
		Unsafe.Add(ref pairs, 7) = Avx512F.Shuffle4x128(g1, g0, LowHalves);
		Unsafe.Add(ref pairs, 8) = Avx512F.Shuffle4x128(g2, g1, LowHalves);
		Unsafe.Add(ref pairs, 9) = Avx512F.Shuffle4x128(g3, g2, LowHalves);
		Unsafe.Add(ref pairs, 10) = Avx512F.Shuffle4x128(g4, g3, LowHalves);
		Unsafe.Add(ref pairs, 11) = Avx512F.Shuffle4x128(g5, g4, LowHalves);
		Unsafe.Add(ref pairs, 12) = Avx512F.Shuffle4x128(g6, g5, LowHalves);
		Unsafe.Add(ref pairs, 13) = Avx512F.Shuffle4x128(g7, g6, LowHalves);
	}

	// φ·y = (y_hi, y_lo + y_hi).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Twist(Vector512<ulong> y)
	{
		return Avx512F.Shuffle4x128(y, y, SwapHalves) + (y & HighHalf());
	}

	// φ·y at index i of right, and the sums of the halves of y and of φ·y.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Twist(ref Vector512<ulong> right, nint i, Vector512<ulong> y)
	{
		Vector512<ulong> twisted = Twist(y);
		Unsafe.Add(ref right, i) = twisted;
		return twisted + y;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> HighHalf()
	{
		return Vector512.Create(0, 0, 0, 0, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue);
	}

	// The lane products of Field448x4Avx2.Product, both halves of a column in one vector: x_k holds (x_lo,k, x_hi,k) and y_n (low_n, high_n), so one product of the two gives P in the low half and Q in the high one, and one product of a vector of Sums and one of Pairs gives R for two values of k, one in each half. Column j of x_lo takes P + Q and column j of x_hi R − P, both in vector j, so the carries of the two halves run side by side; the low halves of pq and of r − pq, one shuffle, and the high halves of pq and of r, another, add up to (P + Q, R − P).
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Product(ref Vector512<ulong> operands, ref Vector512<ulong> result)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		ref Vector512<ulong> x = ref Unsafe.Add(ref operands, Left);
		Vector512<ulong> x0 = x;
		Vector512<ulong> x1 = Unsafe.Add(ref x, 1);
		Vector512<ulong> x2 = Unsafe.Add(ref x, 2);
		Vector512<ulong> x3 = Unsafe.Add(ref x, 3);
		Vector512<ulong> x4 = Unsafe.Add(ref x, 4);
		Vector512<ulong> x5 = Unsafe.Add(ref x, 5);
		Vector512<ulong> x6 = Unsafe.Add(ref x, 6);
		Vector512<ulong> x7 = Unsafe.Add(ref x, 7);
		ref Vector512<ulong> s = ref Unsafe.Add(ref operands, Sums);
		Vector512<ulong> s0 = s;
		Vector512<ulong> s1 = Unsafe.Add(ref s, 1);
		Vector512<ulong> s2 = Unsafe.Add(ref s, 2);
		Vector512<ulong> s3 = Unsafe.Add(ref s, 3);

		// y_n, for n = j − k + 8, lies at index −k of y, and the pair of sum_q and sum_(q−1), for q = j − 2m + 8, at index −2m of pairs.
		ref Vector512<ulong> y = ref Unsafe.Add(ref operands, Right + 7);
		ref Vector512<ulong> pairs = ref Unsafe.Add(ref operands, Pairs + 6);
		Vector512<ulong> carry = Vector512<ulong>.Zero;

		for (nint j = 0; j < 8; ++j)
		{
			Vector512<ulong> pq = M(x0, y) + M(x1, Unsafe.Subtract(ref y, 1)) + (M(x2, Unsafe.Subtract(ref y, 2)) + M(x3, Unsafe.Subtract(ref y, 3))) + (M(x4, Unsafe.Subtract(ref y, 4)) + M(x5, Unsafe.Subtract(ref y, 5)) + (M(x6, Unsafe.Subtract(ref y, 6)) + M(x7, Unsafe.Subtract(ref y, 7))));
			Vector512<ulong> r = M(s0, pairs) + M(s1, Unsafe.Subtract(ref pairs, 2)) + (M(s2, Unsafe.Subtract(ref pairs, 4)) + M(s3, Unsafe.Subtract(ref pairs, 6)));
			Vector512<ulong> column = Avx512F.Shuffle4x128(pq, r - pq, LowHalves) + Avx512F.Shuffle4x128(pq, r, HighHalves) + carry;
			Unsafe.Add(ref result, j) = column & mask;
			carry = column >> Bits;
			y = ref Unsafe.Add(ref y, 1);
			pairs = ref Unsafe.Add(ref pairs, 1);
		}

		Wrap(ref result, carry);
	}

	// The carries out of limbs 7 and 15 into limbs 0 and 8, then one carry out of each into limbs 1 and 9.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Wrap(ref Vector512<ulong> limbs, Vector512<ulong> carry)
	{
		Vector512<ulong> column = limbs + IntoLimbZero(carry);
		limbs = column & Vector512.Create(Mask);
		Unsafe.Add(ref limbs, 1) += column >> Bits;
	}

	// The columns of lane D of the products times u, columns 0 to 7 in one vector and 8 to 15 in another, each limb of lane D in every lane by a load that broadcasts it from the products, which takes no shuffle; two rounds of carries in that form, then column k goes into lane D of limb k, below 2^28 + 2^8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyLaneD(ref Vector512<ulong> products, in Field448x4Avx512 multiplier, ref Field448x4Avx512 state)
	{
		Vector512<ulong> low = Vector512<ulong>.Zero;
		Vector512<ulong> high = Vector512<ulong>.Zero;
		ref ulong limb = ref Unsafe.As<Vector512<ulong>, ulong>(ref products);
		ref Vector512<ulong> factors = ref Unsafe.AsRef(in multiplier.L0);

		for (int k = 0; k < 8; ++k)
		{
			Vector512<ulong> w = Vector512.Create(Unsafe.Add(ref limb, 3));
			Vector512<ulong> v = Vector512.Create(Unsafe.Add(ref limb, 7));
			low += M(w, factors) + M(v, Unsafe.Add(ref factors, 8));
			high += M(w, Unsafe.Add(ref factors, 16)) + M(v, Unsafe.Add(ref factors, 24));
			limb = ref Unsafe.Add(ref limb, 8);
			factors = ref Unsafe.Add(ref factors, 1);
		}

		CarryColumns(ref low, ref high);
		CarryColumns(ref low, ref high);
		Vector512<ulong> laneD = LaneMask(LaneD);
		Vector512<ulong> columns = Vector512.Create(0UL, 0, 0, 0, 8, 8, 8, 8);
		ref Vector512<ulong> result = ref state.L0;

		for (int k = 0; k < 8; ++k)
		{
			Unsafe.Add(ref result, k) = Blend(Unsafe.Add(ref products, k), Avx512F.PermuteVar8x64x2(low, columns, high), laneD);
			columns += Vector512<ulong>.One;
		}
	}

	// One carry from each of the columns 0 to 15 into the next, the one out of column 15 into columns 0 and 8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryColumns(ref Vector512<ulong> low, ref Vector512<ulong> high)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		Vector512<ulong> lowCarries = low >> Bits;
		Vector512<ulong> highCarries = high >> Bits;
		low = (low & mask) + Avx512F.AlignRight64(lowCarries, highCarries, 7);
		high = (high & mask) + Avx512F.AlignRight64(highCarries, lowCarries, 7) + Avx512F.AlignRight64(Vector512<ulong>.Zero, highCarries, 7);
	}

	// All ones in the lanes of each half that lanes sets.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> LaneMask(byte lanes)
	{
		ulong a = (lanes & 1) is 0 ? 0 : ulong.MaxValue;
		ulong b = (lanes & LaneB) is 0 ? 0 : ulong.MaxValue;
		ulong c = (lanes & LaneC) is 0 ? 0 : ulong.MaxValue;
		ulong d = (lanes & LaneD) is 0 ? 0 : ulong.MaxValue;
		return Vector512.Create(a, b, c, d, a, b, c, d);
	}

	// The bits of right where mask is set and of left elsewhere.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Blend(Vector512<ulong> left, Vector512<ulong> right, Vector512<ulong> mask)
	{
		return Avx512F.TernaryLogic(mask, right, left, Select);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> M(Vector512<ulong> x, Vector512<ulong> y)
	{
		return Avx512F.Multiply(x.AsUInt32(), y.AsUInt32());
	}
}
