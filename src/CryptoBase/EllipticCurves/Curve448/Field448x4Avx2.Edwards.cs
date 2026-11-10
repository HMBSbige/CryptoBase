using static CryptoBase.EllipticCurves.Curve448.Field448Blocks<System.Runtime.Intrinsics.Vector256<ulong>, CryptoBase.EllipticCurves.Curve448.Field448Vector256>;

namespace CryptoBase.EllipticCurves.Curve448;

// The point formulas of IEdwardsField448x4: each step writes the operands of its products into the scratch as LadderStep does, the entry of an addition, which SelectBase or LoadAffine writes, being the left operand of the first. Every right operand has m_y ≤ 5 and every pair of lanes m_x·m_y ≤ 6, within what Product takes; where a sum takes 3p, the left operand of the second product is carried once first.
internal partial struct Field448x4Avx2 : IEdwardsField448x4<Field448x4Avx2>
{
	// The limbs of 3p, each at least that of a sum of two products; limb 8 is the smaller.
	private const ulong ThreeP = 3 * Mask;
	private const ulong ThreeP8 = 3 * (Mask - 1);

	// The limbs of 2p in limbs of 56 bits, for the negations of LoadAffine; limb 4 is the smaller.
	private const ulong TwoPWide = (1UL << 57) - 2;
	private const ulong TwoPWide4 = (1UL << 57) - 4;

	private const byte LaneA = 0x03;

	// The left operand of a square doubled, after the products of a step, as SquareProduct takes it.
	private const int Doubled = 72;

	// vpermq controls, named by the lanes they take.
	private const byte Acda = 0b00_11_10_00;
	private const byte Daca = 0b00_10_00_11;
	private const byte Abda = 0b00_11_01_00;

	// The entry of SelectBase, transposed four 56-bit limbs at a time: lanes (y − x, y + x, 2, 2d'xy), each limb then split in two, and lane D negated where negative is set. The entries are canonical, so every lane has m ≤ 1 but lane D negated, which has m ≤ 2.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void SelectBase(int comb, uint index, ulong negative, ref Field448x4Avx2 scratch)
	{
		TwistedBaseTable.SelectPacked(comb, index, negative, out Vector256<ulong> plus0, out Vector256<ulong> plus1, out Vector256<ulong> minus0, out Vector256<ulong> minus1, out Vector256<ulong> product0, out Vector256<ulong> product1);
		Vector256<ulong> negate = Vector256.Create(negative) & Vector256.Create(0, 0, 0, ulong.MaxValue);
		WriteEntry(ref scratch.L0, minus0, plus0, Vector256.CreateScalar(2UL), product0, minus1, plus1, Vector256<ulong>.Zero, product1, negate);
	}

	// (x, y, dxy, x + y), or (−x, y, −dxy, y − x) with the negations taken from 2p in 56-bit limbs, which leaves m ≤ 2 for them and m ≤ 3 for y − x.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LoadAffine(in EdwardsAffinePoint point, bool negative, ref Field448x4Avx2 scratch)
	{
		ref ulong limbs = ref Unsafe.As<EdwardsAffinePoint, ulong>(ref Unsafe.AsRef(in point));
		Vector256<ulong> x0 = Vector256.LoadUnsafe(ref limbs);
		Vector256<ulong> x1 = Vector256.LoadUnsafe(ref limbs, 4);
		Vector256<ulong> y0 = Vector256.LoadUnsafe(ref limbs, 8);
		Vector256<ulong> y1 = Vector256.LoadUnsafe(ref limbs, 12);
		Vector256<ulong> d0 = Vector256.LoadUnsafe(ref limbs, 16);
		Vector256<ulong> d1 = Vector256.LoadUnsafe(ref limbs, 20);

		if (negative)
		{
			Vector256<ulong> twoP0 = Vector256.Create(TwoPWide);
			Vector256<ulong> twoP1 = Vector256.Create(TwoPWide4, TwoPWide, TwoPWide, TwoPWide);
			x0 = twoP0 - x0;
			x1 = twoP1 - x1;
			d0 = twoP0 - d0;
			d1 = twoP1 - d1;
		}

		WriteEntry(ref scratch.L0, x0, y0, d0, x0 + y0, x1, y1, d1, x1 + y1, Vector256<ulong>.Zero);
	}

	// With (p0, p1, p2, p3) = ((X − Y)(y − x), (X + Y)(y + x), 2Z, T·2d'xy) from the first product, E = p1 + p0, H = p1 − p0, F = p2 − p3 and G = p2 + p3 give (E·F, G·H, F·G, E·H) = (X3, Y3, Z3, T3) for a = −1. The right operand (X − Y, X + Y, Z, T) of the first product has m ≤ 3; E and G have m ≤ 2 and F and H m ≤ 3, so no lane of the second exceeds 6.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedAdd(ref Field448x4Avx2 point, ref Field448x4Avx2 scratch)
	{
		ref Vector256<ulong> operands = ref scratch.L0;
		ref Vector256<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector256<ulong> limbs = ref point.L0;
		Vector256<ulong> twoP = Vector256.Create(TwoP);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareRight(ref operands, i, DiffSum(Unsafe.Add(ref limbs, i), twoP), DiffSum(Unsafe.Add(ref limbs, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP)));
		}

		Product(ref operands, ref products);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedAdd(Unsafe.Add(ref products, i), twoP, out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			FinishTwistedAdd(Unsafe.Add(ref products, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			WriteOperands(ref operands, i, leftLow, leftHigh, rightLow, rightHigh);
		}

		Product(ref operands, ref limbs);
	}

	// x = 2XY/(Y² − X²) and y = (Y² + X²)/(2Z² − Y² + X²), as TwistedEdwards448.Double takes them: with (XX, YY, ZZ, SS) = (X², Y², Z², (X + Y)²), E = SS − XX − YY, G = YY − XX, F = 2ZZ + XX − YY and H = XX + YY give (E·F, G·H, F·G, E·H). E takes 3p and has m ≤ 4, G and F 2p, with m ≤ 3 and m ≤ 5: the left operand (E, G, F, E) is carried, and the right one (F, H, G, H) has m ≤ 5.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedDouble(ref Field448x4Avx2 point, ref Field448x4Avx2 scratch)
	{
		ref Vector256<ulong> operands = ref scratch.L0;
		ref Vector256<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(ref point.L0, ref operands);
		SquareProduct(ref operands, ref Unsafe.Add(ref operands, Doubled), ref products);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedDouble(ref Unsafe.Add(ref products, i), Vector256.Create(TwoP), Vector256.Create(ThreeP), out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			FinishTwistedDouble(ref Unsafe.Add(ref products, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP), Vector256.Create(i is 0 ? ThreeP8 : ThreeP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref point.L0);
	}

	// With (A, B, C, S) = (X1x2, Y1y2, T1·dxy, (X1 + Y1)(x2 + y2)) from the first product, E = S − A − B, F = Z1 − C, G = Z1 + C and H = B − A give (E·F, G·H, F·G, E·H) = (X3, Y3, Z3, T3) for a = 1. The right operand (X1, Y1, T1, X1 + Y1) of the first has m ≤ 2 and the entry m ≤ 3, which multiply to at most 6. E takes 3p and has m ≤ 4, F and H 2p, with m ≤ 3: the left operand (E, G, F, E) is carried, and the right one (F, H, G, H) has m ≤ 3.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Add(ref Field448x4Avx2 point, ref Field448x4Avx2 scratch)
	{
		ref Vector256<ulong> operands = ref scratch.L0;
		ref Vector256<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector256<ulong> limbs = ref point.L0;

		for (nint i = 0; i < 8; ++i)
		{
			PrepareRight(ref operands, i, AddOperand(ref Unsafe.Add(ref limbs, i)), AddOperand(ref Unsafe.Add(ref limbs, i + 8)));
		}

		Product(ref operands, ref products);

		for (nint i = 0; i < 8; ++i)
		{
			FinishAdd(ref Unsafe.Add(ref products, i), ref Unsafe.Add(ref limbs, i), Vector256.Create(TwoP), Vector256.Create(ThreeP), out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			FinishAdd(ref Unsafe.Add(ref products, i + 8), ref Unsafe.Add(ref limbs, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP), Vector256.Create(i is 0 ? ThreeP8 : ThreeP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref limbs);
	}

	// x = 2XY/(X² + Y²) and y = (Y² − X²)/(2Z² − X² − Y²), as Edwards448.Double takes them: with (XX, YY, ZZ, SS) = (X², Y², Z², (X + Y)²), the completed point (SS − XX − YY, YY − XX, XX + YY, 2ZZ − XX − YY) goes to extended coordinates by the lanes (2XY, Y² − X², X² + Y², 2XY) times (T, Z, T, Y). The sums that take 3p have m ≤ 4 and 5, and Y² − X² m ≤ 3: the left operand is carried, and the right one has m ≤ 5.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Double(ref Field448x4Avx2 point, ref Field448x4Avx2 scratch)
	{
		ref Vector256<ulong> operands = ref scratch.L0;
		ref Vector256<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(ref point.L0, ref operands);
		SquareProduct(ref operands, ref Unsafe.Add(ref operands, Doubled), ref products);

		for (nint i = 0; i < 8; ++i)
		{
			FinishDouble(ref Unsafe.Add(ref products, i), Vector256.Create(TwoP), Vector256.Create(ThreeP), out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			FinishDouble(ref Unsafe.Add(ref products, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP), Vector256.Create(i is 0 ? ThreeP8 : ThreeP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref point.L0);
	}

	// The squares (X², Y², Z², (X + Y)²) of a doubling, of (X, Y, Z, X + Y), whose lane D has m ≤ 2: its operands as Product takes them, and the left one doubled.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(ref Vector256<ulong> limbs, ref Vector256<ulong> operands)
	{
		ref Vector256<ulong> doubled = ref Unsafe.Add(ref operands, Doubled);

		for (nint i = 0; i < 8; ++i)
		{
			Vector256<ulong> low = SquareOperand(ref Unsafe.Add(ref limbs, i));
			Vector256<ulong> high = SquareOperand(ref Unsafe.Add(ref limbs, i + 8));
			WriteOperands(ref operands, i, low, high, low, high);
			Unsafe.Add(ref doubled, i) = low + low;
			Unsafe.Add(ref doubled, i + 8) = high + high;
			Unsafe.Add(ref doubled, i + 16) = low + high << 1;
		}
	}

	// The left operand of an addition from lanes (A, B, C, D) of four values given four 56-bit limbs at a time: limbs m of the values in group 0 make limbs 2m and 2m + 1, and those in group 1 limbs 2m + 8 and 2m + 9, each transposed into the lanes of a vector and split into its low 28 bits and the rest. Lane D becomes 2p − D where negate is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntry(ref Vector256<ulong> operands, Vector256<ulong> a0, Vector256<ulong> b0, Vector256<ulong> c0, Vector256<ulong> d0, Vector256<ulong> a1, Vector256<ulong> b1, Vector256<ulong> c1, Vector256<ulong> d1, Vector256<ulong> negate)
	{
		Vector256<ulong> ab0 = Avx2.UnpackLow(a0, b0);
		Vector256<ulong> ab1 = Avx2.UnpackHigh(a0, b0);
		Vector256<ulong> cd0 = Avx2.UnpackLow(c0, d0);
		Vector256<ulong> cd1 = Avx2.UnpackHigh(c0, d0);
		Vector256<ulong> ab2 = Avx2.UnpackLow(a1, b1);
		Vector256<ulong> ab3 = Avx2.UnpackHigh(a1, b1);
		Vector256<ulong> cd2 = Avx2.UnpackLow(c1, d1);
		Vector256<ulong> cd3 = Avx2.UnpackHigh(c1, d1);
		WriteEntryLimbs(ref operands, 0, Avx2.Permute2x128(ab0, cd0, 0x20), Avx2.Permute2x128(ab2, cd2, 0x20), negate);
		WriteEntryLimbs(ref operands, 2, Avx2.Permute2x128(ab1, cd1, 0x20), Avx2.Permute2x128(ab3, cd3, 0x20), negate);
		WriteEntryLimbs(ref operands, 4, Avx2.Permute2x128(ab0, cd0, 0x31), Avx2.Permute2x128(ab2, cd2, 0x31), negate);
		WriteEntryLimbs(ref operands, 6, Avx2.Permute2x128(ab1, cd1, 0x31), Avx2.Permute2x128(ab3, cd3, 0x31), negate);
	}

	// (X − Y, X + Y, Z, T) from (X, Y, Z, T), X − Y taking 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> DiffSum(Vector256<ulong> limb, Vector256<ulong> twoP)
	{
		Vector256<ulong> swapped = Swap(limb);
		return Blend(limb + Blend(twoP - swapped, swapped, LaneB), limb, LaneC | LaneD);
	}

	// (X, Y, T, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> AddOperand(ref Vector256<ulong> limb)
	{
		return Avx2.Permute4x64(limb, Abda) + Blend(Vector256<ulong>.Zero, Lane(ref limb, 1), LaneD);
	}

	// (X, Y, Z, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> SquareOperand(ref Vector256<ulong> limb)
	{
		return Blend(limb, Lane(ref limb, 0) + Lane(ref limb, 1), LaneD);
	}

	// (E, G, F, E) and (F, H, G, H) from (p0, p1, p2, p3) and its swap (p1, p0, p3, p2): the sums (E, E, G, G) and the differences (H, ·, ·, F).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedAdd(Vector256<ulong> limb, Vector256<ulong> twoP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> swapped = Swap(limb);
		Vector256<ulong> sums = limb + swapped;
		Vector256<ulong> differences = swapped + twoP - limb;
		left = Avx2.Permute4x64(Blend(sums, differences, LaneD), Acda);
		right = Avx2.Permute4x64(Blend(sums, differences, LaneA | LaneD), Daca);
	}

	// (E, G, F, E) and (F, H, G, H) from (XX, YY, ZZ, SS), each lane of each from the four broadcast.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedDouble(ref Vector256<ulong> limb, Vector256<ulong> twoP, Vector256<ulong> threeP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> xx = Lane(ref limb, 0);
		Vector256<ulong> yy = Lane(ref limb, 1);
		Vector256<ulong> zz = Lane(ref limb, 2);
		Vector256<ulong> h = xx + yy;
		Vector256<ulong> e = Lane(ref limb, 3) + threeP - h;
		Vector256<ulong> g = yy + twoP - xx;
		Vector256<ulong> f = zz + zz + xx + twoP - yy;
		left = Blend(Blend(e, g, LaneB), f, LaneC);
		right = Blend(Blend(f, h, LaneB | LaneD), g, LaneC);
	}

	// (E, G, F, E) and (F, H, G, H) from (A, B, C, S) and lane C, Z1, of the point.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(ref Vector256<ulong> limb, ref Vector256<ulong> point, Vector256<ulong> twoP, Vector256<ulong> threeP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> a = Lane(ref limb, 0);
		Vector256<ulong> b = Lane(ref limb, 1);
		Vector256<ulong> c = Lane(ref limb, 2);
		Vector256<ulong> z = Lane(ref point, 2);
		Vector256<ulong> e = Lane(ref limb, 3) + threeP - (a + b);
		Vector256<ulong> f = z + twoP - c;
		Vector256<ulong> g = z + c;
		Vector256<ulong> h = b + twoP - a;
		left = Blend(Blend(e, g, LaneB), f, LaneC);
		right = Blend(Blend(f, h, LaneB | LaneD), g, LaneC);
	}

	// (2XY, Y² − X², X² + Y², 2XY) and (2Z² − X² − Y², X² + Y², 2Z² − X² − Y², Y² − X²) from (XX, YY, ZZ, SS).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(ref Vector256<ulong> limb, Vector256<ulong> twoP, Vector256<ulong> threeP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> xx = Lane(ref limb, 0);
		Vector256<ulong> yy = Lane(ref limb, 1);
		Vector256<ulong> zz = Lane(ref limb, 2);
		Vector256<ulong> sum = xx + yy;
		Vector256<ulong> x = Lane(ref limb, 3) + threeP - sum;
		Vector256<ulong> y = yy + twoP - xx;
		Vector256<ulong> t = zz + zz + threeP - sum;
		left = Blend(Blend(x, y, LaneB), sum, LaneC);
		right = Blend(Blend(t, sum, LaneB), y, LaneD);
	}
}
