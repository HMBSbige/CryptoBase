namespace CryptoBase.EllipticCurves.Curve448;

// The point formulas of Field448x4Avx2 on both halves of each vector at once, with the operands written by WriteLeft and WriteRight.
internal partial struct Field448x4Avx512 : IEdwardsField448x4<Field448x4Avx512>
{
	private const ulong ThreeP = 3 * Mask;
	private const ulong ThreeP8 = 3 * (Mask - 1);

	private const ulong TwoPWide = (1UL << 57) - 2;
	private const ulong TwoPWide4 = (1UL << 57) - 4;

	private const byte LaneA = 0b0001;

	// vpermq controls within each half, named by the lanes they take.
	private const byte Aaaa = 0b00_00_00_00;
	private const byte Bbbb = 0b01_01_01_01;
	private const byte Cccc = 0b10_10_10_10;
	private const byte Dddd = 0b11_11_11_11;
	private const byte Acda = 0b00_11_10_00;
	private const byte Daca = 0b00_10_00_11;
	private const byte Abda = 0b00_11_01_00;

	// As Field448x4Avx2.SelectBase, the 56-bit limbs m and m + 4 of the four lanes gathered into the halves of one vector before the split.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void SelectBase(int comb, uint index, ulong negative, ref Field448x4Avx512 scratch)
	{
		TwistedBaseTable.SelectPacked(comb, index, negative, out Vector512<ulong> plus, out Vector512<ulong> minus, out Vector512<ulong> product);
		WriteEntry(ref scratch.L0, minus, plus, Vector512.CreateScalar(2UL), product, Vector512.Create(negative) & LaneMask(LaneD));
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LoadAffine(in EdwardsAffinePoint point, bool negative, ref Field448x4Avx512 scratch)
	{
		ref ulong limbs = ref Unsafe.As<EdwardsAffinePoint, ulong>(ref Unsafe.AsRef(in point));
		Vector512<ulong> x = Vector512.LoadUnsafe(ref limbs);
		Vector512<ulong> y = Vector512.LoadUnsafe(ref limbs, 8);
		Vector512<ulong> d = Vector512.LoadUnsafe(ref limbs, 16);

		if (negative)
		{
			Vector512<ulong> twoP = Vector512.Create(TwoPWide, TwoPWide, TwoPWide, TwoPWide, TwoPWide4, TwoPWide, TwoPWide, TwoPWide);
			x = twoP - x;
			d = twoP - d;
		}

		WriteEntry(ref scratch.L0, x, y, d, x + y, Vector512<ulong>.Zero);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedAdd(ref Field448x4Avx512 point, ref Field448x4Avx512 scratch)
	{
		ref Vector512<ulong> operands = ref scratch.L0;
		ref Vector512<ulong> products = ref Unsafe.Add(ref operands, Products);
		Vector512<ulong> twoP0 = Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8);
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		WriteRight(ref operands, DiffSum(point.L0, twoP0), DiffSum(point.L1, twoP), DiffSum(point.L2, twoP), DiffSum(point.L3, twoP), DiffSum(point.L4, twoP), DiffSum(point.L5, twoP), DiffSum(point.L6, twoP), DiffSum(point.L7, twoP));
		Product(ref operands, ref products);
		FinishTwistedAdd(products, twoP0, out Vector512<ulong> left0, out Vector512<ulong> right0);
		FinishTwistedAdd(Unsafe.Add(ref products, 1), twoP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		FinishTwistedAdd(Unsafe.Add(ref products, 2), twoP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		FinishTwistedAdd(Unsafe.Add(ref products, 3), twoP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		FinishTwistedAdd(Unsafe.Add(ref products, 4), twoP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		FinishTwistedAdd(Unsafe.Add(ref products, 5), twoP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		FinishTwistedAdd(Unsafe.Add(ref products, 6), twoP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		FinishTwistedAdd(Unsafe.Add(ref products, 7), twoP, out Vector512<ulong> left7, out Vector512<ulong> right7);
		WriteLeft(ref operands, left0, left1, left2, left3, left4, left5, left6, left7);
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
		Product(ref operands, ref point.L0);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedDouble(ref Field448x4Avx512 point, ref Field448x4Avx512 scratch)
	{
		ref Vector512<ulong> operands = ref scratch.L0;
		ref Vector512<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(in point, ref operands);
		Product(ref operands, ref products);
		Vector512<ulong> twoP0 = Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8);
		Vector512<ulong> threeP0 = Vector512.Create(ThreeP, ThreeP, ThreeP, ThreeP, ThreeP8, ThreeP8, ThreeP8, ThreeP8);
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		Vector512<ulong> threeP = Vector512.Create(ThreeP);
		FinishTwistedDouble(products, twoP0, threeP0, out Vector512<ulong> left0, out Vector512<ulong> right0);
		FinishTwistedDouble(Unsafe.Add(ref products, 1), twoP, threeP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		FinishTwistedDouble(Unsafe.Add(ref products, 2), twoP, threeP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		FinishTwistedDouble(Unsafe.Add(ref products, 3), twoP, threeP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		FinishTwistedDouble(Unsafe.Add(ref products, 4), twoP, threeP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		FinishTwistedDouble(Unsafe.Add(ref products, 5), twoP, threeP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		FinishTwistedDouble(Unsafe.Add(ref products, 6), twoP, threeP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		FinishTwistedDouble(Unsafe.Add(ref products, 7), twoP, threeP, out Vector512<ulong> left7, out Vector512<ulong> right7);
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
		WriteCarriedLeft(ref operands, left0, left1, left2, left3, left4, left5, left6, left7);
		Product(ref operands, ref point.L0);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Add(ref Field448x4Avx512 point, ref Field448x4Avx512 scratch)
	{
		ref Vector512<ulong> operands = ref scratch.L0;
		ref Vector512<ulong> products = ref Unsafe.Add(ref operands, Products);
		WriteRight(ref operands, AddOperand(point.L0), AddOperand(point.L1), AddOperand(point.L2), AddOperand(point.L3), AddOperand(point.L4), AddOperand(point.L5), AddOperand(point.L6), AddOperand(point.L7));
		Product(ref operands, ref products);
		Vector512<ulong> twoP0 = Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8);
		Vector512<ulong> threeP0 = Vector512.Create(ThreeP, ThreeP, ThreeP, ThreeP, ThreeP8, ThreeP8, ThreeP8, ThreeP8);
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		Vector512<ulong> threeP = Vector512.Create(ThreeP);
		FinishAdd(products, point.L0, twoP0, threeP0, out Vector512<ulong> left0, out Vector512<ulong> right0);
		FinishAdd(Unsafe.Add(ref products, 1), point.L1, twoP, threeP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		FinishAdd(Unsafe.Add(ref products, 2), point.L2, twoP, threeP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		FinishAdd(Unsafe.Add(ref products, 3), point.L3, twoP, threeP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		FinishAdd(Unsafe.Add(ref products, 4), point.L4, twoP, threeP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		FinishAdd(Unsafe.Add(ref products, 5), point.L5, twoP, threeP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		FinishAdd(Unsafe.Add(ref products, 6), point.L6, twoP, threeP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		FinishAdd(Unsafe.Add(ref products, 7), point.L7, twoP, threeP, out Vector512<ulong> left7, out Vector512<ulong> right7);
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
		WriteCarriedLeft(ref operands, left0, left1, left2, left3, left4, left5, left6, left7);
		Product(ref operands, ref point.L0);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Double(ref Field448x4Avx512 point, ref Field448x4Avx512 scratch)
	{
		ref Vector512<ulong> operands = ref scratch.L0;
		ref Vector512<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(in point, ref operands);
		Product(ref operands, ref products);
		Vector512<ulong> twoP0 = Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8);
		Vector512<ulong> threeP0 = Vector512.Create(ThreeP, ThreeP, ThreeP, ThreeP, ThreeP8, ThreeP8, ThreeP8, ThreeP8);
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		Vector512<ulong> threeP = Vector512.Create(ThreeP);
		FinishDouble(products, twoP0, threeP0, out Vector512<ulong> left0, out Vector512<ulong> right0);
		FinishDouble(Unsafe.Add(ref products, 1), twoP, threeP, out Vector512<ulong> left1, out Vector512<ulong> right1);
		FinishDouble(Unsafe.Add(ref products, 2), twoP, threeP, out Vector512<ulong> left2, out Vector512<ulong> right2);
		FinishDouble(Unsafe.Add(ref products, 3), twoP, threeP, out Vector512<ulong> left3, out Vector512<ulong> right3);
		FinishDouble(Unsafe.Add(ref products, 4), twoP, threeP, out Vector512<ulong> left4, out Vector512<ulong> right4);
		FinishDouble(Unsafe.Add(ref products, 5), twoP, threeP, out Vector512<ulong> left5, out Vector512<ulong> right5);
		FinishDouble(Unsafe.Add(ref products, 6), twoP, threeP, out Vector512<ulong> left6, out Vector512<ulong> right6);
		FinishDouble(Unsafe.Add(ref products, 7), twoP, threeP, out Vector512<ulong> left7, out Vector512<ulong> right7);
		WriteRight(ref operands, right0, right1, right2, right3, right4, right5, right6, right7);
		WriteCarriedLeft(ref operands, left0, left1, left2, left3, left4, left5, left6, left7);
		Product(ref operands, ref point.L0);
	}

	// The product of (X, Y, Z, X + Y) by itself.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(in Field448x4Avx512 point, ref Vector512<ulong> operands)
	{
		Vector512<ulong> v0 = SquareOperand(point.L0);
		Vector512<ulong> v1 = SquareOperand(point.L1);
		Vector512<ulong> v2 = SquareOperand(point.L2);
		Vector512<ulong> v3 = SquareOperand(point.L3);
		Vector512<ulong> v4 = SquareOperand(point.L4);
		Vector512<ulong> v5 = SquareOperand(point.L5);
		Vector512<ulong> v6 = SquareOperand(point.L6);
		Vector512<ulong> v7 = SquareOperand(point.L7);
		WriteLeft(ref operands, v0, v1, v2, v3, v4, v5, v6, v7);
		WriteRight(ref operands, v0, v1, v2, v3, v4, v5, v6, v7);
	}

	// As Field448x4Avx2.WriteEntry: w_m holds the 56-bit limbs m of the four lanes in its low half and m + 4 in its high half, which split into vectors 2m and 2m + 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntry(ref Vector512<ulong> operands, Vector512<ulong> a, Vector512<ulong> b, Vector512<ulong> c, Vector512<ulong> d, Vector512<ulong> negate)
	{
		Vector512<ulong> abEven = Avx512F.UnpackLow(a, b);
		Vector512<ulong> abOdd = Avx512F.UnpackHigh(a, b);
		Vector512<ulong> cdEven = Avx512F.UnpackLow(c, d);
		Vector512<ulong> cdOdd = Avx512F.UnpackHigh(c, d);
		Vector512<ulong> first = Vector512.Create(0UL, 1, 8, 9, 4, 5, 12, 13);
		Vector512<ulong> second = Vector512.Create(2UL, 3, 10, 11, 6, 7, 14, 15);
		Vector512<ulong> w0 = Avx512F.PermuteVar8x64x2(abEven, first, cdEven);
		Vector512<ulong> w1 = Avx512F.PermuteVar8x64x2(abOdd, first, cdOdd);
		Vector512<ulong> w2 = Avx512F.PermuteVar8x64x2(abEven, second, cdEven);
		Vector512<ulong> w3 = Avx512F.PermuteVar8x64x2(abOdd, second, cdOdd);
		Vector512<ulong> mask = Vector512.Create(Mask);
		Vector512<ulong> twoP = Vector512.Create(TwoP);
		WriteLeft(ref operands, NegateUnder(w0 & mask, Vector512.Create(TwoP, TwoP, TwoP, TwoP, TwoP8, TwoP8, TwoP8, TwoP8), negate), NegateUnder(w0 >> Bits, twoP, negate), NegateUnder(w1 & mask, twoP, negate), NegateUnder(w1 >> Bits, twoP, negate), NegateUnder(w2 & mask, twoP, negate), NegateUnder(w2 >> Bits, twoP, negate), NegateUnder(w3 & mask, twoP, negate), NegateUnder(w3 >> Bits, twoP, negate));
	}

	// value, or 2p − value where negate is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> NegateUnder(Vector512<ulong> value, Vector512<ulong> twoP, Vector512<ulong> negate)
	{
		return (value ^ negate) + (negate & twoP + Vector512<ulong>.One);
	}

	// The left operand carried once, as FinishLadder carries it.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteCarriedLeft(ref Vector512<ulong> operands, Vector512<ulong> left0, Vector512<ulong> left1, Vector512<ulong> left2, Vector512<ulong> left3, Vector512<ulong> left4, Vector512<ulong> left5, Vector512<ulong> left6, Vector512<ulong> left7)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		WriteLeft(ref operands, (left0 & mask) + IntoLimbZero(left7 >> Bits), (left1 & mask) + (left0 >> Bits), (left2 & mask) + (left1 >> Bits), (left3 & mask) + (left2 >> Bits), (left4 & mask) + (left3 >> Bits), (left5 & mask) + (left4 >> Bits), (left6 & mask) + (left5 >> Bits), (left7 & mask) + (left6 >> Bits));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Swap(Vector512<ulong> limb)
	{
		return Avx512F.Shuffle(limb.AsUInt32(), Badc).AsUInt64();
	}

	// (X − Y, X + Y, Z, T) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> DiffSum(Vector512<ulong> limb, Vector512<ulong> twoP)
	{
		Vector512<ulong> swapped = Swap(limb);
		return Blend(limb + Blend(twoP - swapped, swapped, LaneMask(LaneB)), limb, LaneMask(LaneC | LaneD));
	}

	// (X, Y, T, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> AddOperand(Vector512<ulong> limb)
	{
		return Avx512F.Permute4x64(limb, Abda) + (Avx512F.Permute4x64(limb, Bbbb) & LaneMask(LaneD));
	}

	// (X, Y, Z, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> SquareOperand(Vector512<ulong> limb)
	{
		return Blend(limb, Avx512F.Permute4x64(limb, Aaaa) + Avx512F.Permute4x64(limb, Bbbb), LaneMask(LaneD));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedAdd(Vector512<ulong> limb, Vector512<ulong> twoP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> swapped = Swap(limb);
		Vector512<ulong> sums = limb + swapped;
		Vector512<ulong> differences = swapped + twoP - limb;
		left = Avx512F.Permute4x64(Blend(sums, differences, LaneMask(LaneD)), Acda);
		right = Avx512F.Permute4x64(Blend(sums, differences, LaneMask(LaneA | LaneD)), Daca);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedDouble(Vector512<ulong> limb, Vector512<ulong> twoP, Vector512<ulong> threeP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> xx = Avx512F.Permute4x64(limb, Aaaa);
		Vector512<ulong> yy = Avx512F.Permute4x64(limb, Bbbb);
		Vector512<ulong> zz = Avx512F.Permute4x64(limb, Cccc);
		Vector512<ulong> h = xx + yy;
		Vector512<ulong> e = Avx512F.Permute4x64(limb, Dddd) + threeP - h;
		Vector512<ulong> g = yy + twoP - xx;
		Vector512<ulong> f = zz + zz + xx + twoP - yy;
		left = Blend(Blend(e, g, LaneMask(LaneB)), f, LaneMask(LaneC));
		right = Blend(Blend(f, h, LaneMask(LaneB | LaneD)), g, LaneMask(LaneC));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector512<ulong> limb, Vector512<ulong> point, Vector512<ulong> twoP, Vector512<ulong> threeP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> a = Avx512F.Permute4x64(limb, Aaaa);
		Vector512<ulong> b = Avx512F.Permute4x64(limb, Bbbb);
		Vector512<ulong> c = Avx512F.Permute4x64(limb, Cccc);
		Vector512<ulong> z = Avx512F.Permute4x64(point, Cccc);
		Vector512<ulong> e = Avx512F.Permute4x64(limb, Dddd) + threeP - (a + b);
		Vector512<ulong> f = z + twoP - c;
		Vector512<ulong> g = z + c;
		Vector512<ulong> h = b + twoP - a;
		left = Blend(Blend(e, g, LaneMask(LaneB)), f, LaneMask(LaneC));
		right = Blend(Blend(f, h, LaneMask(LaneB | LaneD)), g, LaneMask(LaneC));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector512<ulong> limb, Vector512<ulong> twoP, Vector512<ulong> threeP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> xx = Avx512F.Permute4x64(limb, Aaaa);
		Vector512<ulong> yy = Avx512F.Permute4x64(limb, Bbbb);
		Vector512<ulong> zz = Avx512F.Permute4x64(limb, Cccc);
		Vector512<ulong> sum = xx + yy;
		Vector512<ulong> x = Avx512F.Permute4x64(limb, Dddd) + threeP - sum;
		Vector512<ulong> y = yy + twoP - xx;
		Vector512<ulong> t = zz + zz + threeP - sum;
		left = Blend(Blend(x, y, LaneMask(LaneB)), sum, LaneMask(LaneC));
		right = Blend(Blend(t, sum, LaneMask(LaneB)), y, LaneMask(LaneD));
	}
}
