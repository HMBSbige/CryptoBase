using static CryptoBase.EllipticCurves.Curve448.Field448Blocks<System.Runtime.Intrinsics.Vector128<ulong>, CryptoBase.EllipticCurves.Curve448.Field448Vector128>;

namespace CryptoBase.EllipticCurves.Curve448;

// The point formulas of Field448x4Avx2 pair by pair: lanes A and B of each operand go to the products of pair AB and lanes C and D to those of pair CD, so the shuffles of a formula move values between the pairs by unpacking.
internal partial struct Field448x4Sse41 : IEdwardsField448x4<Field448x4Sse41>
{
	private const ulong ThreeP = 3 * Mask;
	private const ulong ThreeP8 = 3 * (Mask - 1);

	// The doubled operands of the squares of a step, those of pair AB after the products and those of pair CD after them, DoubledLength vectors each.
	private const int Doubled = 144;
	private const int DoubledLength = 24;

	// The lanes (y − x, y + x) and (2, 2d'xy) of the entry, from vectors of two 56-bit limbs that TwistedBaseTable.SelectPacked gives, with 2d'xy negated where negative is set.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void SelectBase(int comb, uint index, ulong negative, ref Field448x4Sse41 scratch)
	{
		TwistedBaseTable.SelectPacked(comb, index, negative, out Vector128<ulong> plus0, out Vector128<ulong> plus1, out Vector128<ulong> plus2, out Vector128<ulong> plus3, out Vector128<ulong> minus0, out Vector128<ulong> minus1, out Vector128<ulong> minus2, out Vector128<ulong> minus3, out Vector128<ulong> product0, out Vector128<ulong> product1, out Vector128<ulong> product2, out Vector128<ulong> product3);
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		Vector128<ulong> negate = Vector128.Create(0, negative);
		WriteEntryPairs(ref operands, 0, minus0, plus0, minus2, plus2, Vector128<ulong>.Zero);
		WriteEntryPairs(ref operands, 4, minus1, plus1, minus3, plus3, Vector128<ulong>.Zero);
		WriteEntryPairs(ref second, 0, Vector128.CreateScalar(2UL), product0, Vector128<ulong>.Zero, product2, negate);
		WriteEntryPairs(ref second, 4, Vector128<ulong>.Zero, product1, Vector128<ulong>.Zero, product3, negate);
	}

	// Limbs i to i + 3 and i + 8 to i + 11 of the left operand of a pair from lanes a and b of two 56-bit limbs of the low half and the two 8 above them, the second lane negated where negate is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntryPairs(ref Vector128<ulong> operands, nint i, Vector128<ulong> aLow, Vector128<ulong> bLow, Vector128<ulong> aHigh, Vector128<ulong> bHigh, Vector128<ulong> negate)
	{
		WriteEntryLimbs(ref operands, i, Sse2.UnpackLow(aLow, bLow), Sse2.UnpackLow(aHigh, bHigh), negate);
		WriteEntryLimbs(ref operands, i + 2, Sse2.UnpackHigh(aLow, bLow), Sse2.UnpackHigh(aHigh, bHigh), negate);
	}

	// The negations are those of Field448.Negate, which leave them tight, and y − x m ≤ 2.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LoadAffine(in EdwardsAffinePoint point, bool negative, ref Field448x4Sse41 scratch)
	{
		Field448 x = point.X;
		Field448 product = point.DXY;

		if (negative)
		{
			Field448.Negate(in x, out x);
			Field448.Negate(in product, out product);
		}

		Field448.Add(in x, in point.Y, out Field448 sum);
		WriteEntry(ref scratch.AB.L0, in x, in point.Y, in product, in sum);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedAdd(ref Field448x4Sse41 point, ref Field448x4Sse41 scratch)
	{
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<ulong> ab = ref point.AB.L0;
		ref Vector128<ulong> cd = ref point.CD.L0;
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareRight(ref operands, i, DiffSum(Unsafe.Add(ref ab, i), Vector128.Create(TwoP)), DiffSum(Unsafe.Add(ref ab, i + 8), twoPHigh));
			PrepareRight(ref second, i, Unsafe.Add(ref cd, i), Unsafe.Add(ref cd, i + 8));
			twoPHigh = Vector128.Create(TwoP);
		}

		Pair.Product(ref operands, ref products);
		Pair.Product(ref second, ref Unsafe.Add(ref products, 16));
		ref Vector128<ulong> productsCD = ref Unsafe.Add(ref products, 16);
		twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedAdd(Unsafe.Add(ref products, i), Unsafe.Add(ref productsCD, i), Vector128.Create(TwoP), out Vector128<ulong> leftLowAB, out Vector128<ulong> leftLowCD, out Vector128<ulong> rightLowAB, out Vector128<ulong> rightLowCD);
			FinishTwistedAdd(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref productsCD, i + 8), twoPHigh, out Vector128<ulong> leftHighAB, out Vector128<ulong> leftHighCD, out Vector128<ulong> rightHighAB, out Vector128<ulong> rightHighCD);
			WriteOperands(ref operands, i, leftLowAB, leftHighAB, rightLowAB, rightHighAB);
			WriteOperands(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
			twoPHigh = Vector128.Create(TwoP);
		}

		Pair.Product(ref operands, ref ab);
		Pair.Product(ref second, ref cd);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedDouble(ref Field448x4Sse41 point, ref Field448x4Sse41 scratch)
	{
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<ulong> productsCD = ref Unsafe.Add(ref products, 16);
		ref Vector128<ulong> doubled = ref Unsafe.Add(ref operands, Doubled);
		PrepareDouble(ref point, ref operands);
		SquareProduct(ref operands, ref doubled, ref products);
		SquareProduct(ref second, ref Unsafe.Add(ref doubled, DoubledLength), ref productsCD);
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);
		Vector128<ulong> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedDouble(Unsafe.Add(ref products, i), Unsafe.Add(ref productsCD, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<ulong> leftLowAB, out Vector128<ulong> leftLowCD, out Vector128<ulong> rightLowAB, out Vector128<ulong> rightLowCD);
			FinishTwistedDouble(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref productsCD, i + 8), twoPHigh, threePHigh, out Vector128<ulong> leftHighAB, out Vector128<ulong> leftHighCD, out Vector128<ulong> rightHighAB, out Vector128<ulong> rightHighCD);
			WriteUncarried(ref operands, i, leftLowAB, leftHighAB, rightLowAB, rightHighAB);
			WriteUncarried(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		CarryLeft(ref second);
		Pair.Product(ref operands, ref point.AB.L0);
		Pair.Product(ref second, ref point.CD.L0);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Add(ref Field448x4Sse41 point, ref Field448x4Sse41 scratch)
	{
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<ulong> productsCD = ref Unsafe.Add(ref products, 16);
		ref Vector128<ulong> ab = ref point.AB.L0;
		ref Vector128<ulong> cd = ref point.CD.L0;

		for (nint i = 0; i < 8; ++i)
		{
			Vector128<ulong> low = Unsafe.Add(ref ab, i);
			Vector128<ulong> high = Unsafe.Add(ref ab, i + 8);
			PrepareRight(ref operands, i, low, high);
			PrepareRight(ref second, i, Previous(Unsafe.Add(ref cd, i), low + Swap(low)), Previous(Unsafe.Add(ref cd, i + 8), high + Swap(high)));
		}

		Pair.Product(ref operands, ref products);
		Pair.Product(ref second, ref productsCD);
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);
		Vector128<ulong> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishAdd(Unsafe.Add(ref products, i), Unsafe.Add(ref productsCD, i), Unsafe.Add(ref cd, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<ulong> leftLowAB, out Vector128<ulong> leftLowCD, out Vector128<ulong> rightLowAB, out Vector128<ulong> rightLowCD);
			FinishAdd(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref productsCD, i + 8), Unsafe.Add(ref cd, i + 8), twoPHigh, threePHigh, out Vector128<ulong> leftHighAB, out Vector128<ulong> leftHighCD, out Vector128<ulong> rightHighAB, out Vector128<ulong> rightHighCD);
			WriteUncarried(ref operands, i, leftLowAB, leftHighAB, rightLowAB, rightHighAB);
			WriteUncarried(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		CarryLeft(ref second);
		Pair.Product(ref operands, ref ab);
		Pair.Product(ref second, ref cd);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Double(ref Field448x4Sse41 point, ref Field448x4Sse41 scratch)
	{
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<ulong> productsCD = ref Unsafe.Add(ref products, 16);
		ref Vector128<ulong> doubled = ref Unsafe.Add(ref operands, Doubled);
		PrepareDouble(ref point, ref operands);
		SquareProduct(ref operands, ref doubled, ref products);
		SquareProduct(ref second, ref Unsafe.Add(ref doubled, DoubledLength), ref productsCD);
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);
		Vector128<ulong> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishDouble(Unsafe.Add(ref products, i), Unsafe.Add(ref productsCD, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<ulong> leftLowAB, out Vector128<ulong> leftLowCD, out Vector128<ulong> rightLowAB, out Vector128<ulong> rightLowCD);
			FinishDouble(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref productsCD, i + 8), twoPHigh, threePHigh, out Vector128<ulong> leftHighAB, out Vector128<ulong> leftHighCD, out Vector128<ulong> rightHighAB, out Vector128<ulong> rightHighCD);
			WriteUncarried(ref operands, i, leftLowAB, leftHighAB, rightLowAB, rightHighAB);
			WriteUncarried(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		CarryLeft(ref second);
		Pair.Product(ref operands, ref point.AB.L0);
		Pair.Product(ref second, ref point.CD.L0);
	}

	// The squares of (X, Y) and (Z, X + Y): their operands as Pair.Product takes them, and the left ones doubled.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(ref Field448x4Sse41 point, ref Vector128<ulong> operands)
	{
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> doubled = ref Unsafe.Add(ref operands, Doubled);
		ref Vector128<ulong> ab = ref point.AB.L0;
		ref Vector128<ulong> cd = ref point.CD.L0;

		for (nint i = 0; i < 8; ++i)
		{
			Vector128<ulong> low = Unsafe.Add(ref ab, i);
			Vector128<ulong> high = Unsafe.Add(ref ab, i + 8);
			Vector128<ulong> lowCD = Blend(Unsafe.Add(ref cd, i), low + Swap(low));
			Vector128<ulong> highCD = Blend(Unsafe.Add(ref cd, i + 8), high + Swap(high));
			Pair.WriteSquareOperands(ref operands, ref doubled, i, low, high);
			Pair.WriteSquareOperands(ref second, ref Unsafe.Add(ref doubled, DoubledLength), i, lowCD, highCD);
		}
	}

	// The left operand of an addition from lanes (a, b) and (c, d): the 56-bit limbs k of each pair, for k below 4, make limbs 2k and 2k + 1, and limbs k + 4 make limbs 2k + 8 and 2k + 9.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntry(ref Vector128<ulong> operands, in Field448 a, in Field448 b, in Field448 c, in Field448 d)
	{
		WriteEntry(ref operands, in a, in b);
		WriteEntry(ref Unsafe.Add(ref operands, Second), in c, in d);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntry(ref Vector128<ulong> operands, in Field448 a, in Field448 b)
	{
		ref ulong first = ref Unsafe.AsRef(in a.L0);
		ref ulong second = ref Unsafe.AsRef(in b.L0);

		for (nint k = 0; k < 4; k += 2)
		{
			Vector128<ulong> lowA = Vector128.LoadUnsafe(ref first, (nuint)k);
			Vector128<ulong> lowB = Vector128.LoadUnsafe(ref second, (nuint)k);
			Vector128<ulong> highA = Vector128.LoadUnsafe(ref first, (nuint)k + 4);
			Vector128<ulong> highB = Vector128.LoadUnsafe(ref second, (nuint)k + 4);
			WriteEntryPairs(ref operands, 2 * k, lowA, lowB, highA, highB, Vector128<ulong>.Zero);
		}
	}

	// Limbs i and i + 8 of the left operand, to be carried, and of the right one.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteUncarried(ref Vector128<ulong> operands, nint i, Vector128<ulong> leftLow, Vector128<ulong> leftHigh, Vector128<ulong> rightLow, Vector128<ulong> rightHigh)
	{
		Unsafe.Add(ref operands, Left + i) = leftLow;
		Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
		PrepareRight(ref operands, i, rightLow, rightHigh);
	}

	// (X − Y, X + Y) from (X, Y).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> DiffSum(Vector128<ulong> limb, Vector128<ulong> twoP)
	{
		Vector128<ulong> swapped = Swap(limb);
		return limb + Blend(twoP - swapped, swapped);
	}

	// From (p0, p1) and (p2, p3): (E, G), (F, E), (F, H) and (G, H).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedAdd(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);
		Vector128<ulong> e = ab + swappedAB;
		Vector128<ulong> h = swappedAB + twoP - ab;
		Vector128<ulong> g = cd + swappedCD;
		Vector128<ulong> f = cd + twoP - swappedCD;
		leftAB = Sse2.UnpackLow(e, g);
		leftCD = Sse2.UnpackLow(f, e);
		rightAB = Sse2.UnpackLow(f, h);
		rightCD = Sse2.UnpackLow(g, h);
	}

	// From (XX, YY) and (ZZ, SS), lane 0 of each of e, f, g and h holding E, F, G and H.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedDouble(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> twoP, Vector128<ulong> threeP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> h = ab + swappedAB;
		Vector128<ulong> g = swappedAB + twoP - ab;
		Vector128<ulong> e = Swap(cd) + threeP - h;
		Vector128<ulong> f = cd + cd + Swap(g);
		leftAB = Sse2.UnpackLow(e, g);
		leftCD = Sse2.UnpackLow(f, e);
		rightAB = Sse2.UnpackLow(f, h);
		rightCD = Sse2.UnpackLow(g, h);
	}

	// From (A, B) and (C, S) and lanes (Z1, T1) of the point.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> point, Vector128<ulong> twoP, Vector128<ulong> threeP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> h = swappedAB + twoP - ab;
		Vector128<ulong> e = Swap(cd) + threeP - (ab + swappedAB);
		Vector128<ulong> f = point + twoP - cd;
		Vector128<ulong> g = point + cd;
		leftAB = Sse2.UnpackLow(e, g);
		leftCD = Sse2.UnpackLow(f, e);
		rightAB = Sse2.UnpackLow(f, h);
		rightCD = Sse2.UnpackLow(g, h);
	}

	// From (XX, YY) and (ZZ, SS): (2XY, Y² − X²), (X² + Y², 2XY), (2Z² − X² − Y², X² + Y²) and (2Z² − X² − Y², Y² − X²).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> twoP, Vector128<ulong> threeP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> s = ab + swappedAB;
		Vector128<ulong> y = swappedAB + twoP - ab;
		Vector128<ulong> x = Swap(cd) + threeP - s;
		Vector128<ulong> t = cd + cd + threeP - s;
		leftAB = Sse2.UnpackLow(x, y);
		leftCD = Sse2.UnpackLow(s, x);
		rightAB = Sse2.UnpackLow(t, s);
		rightCD = Sse2.UnpackLow(t, y);
	}

	internal partial struct Pair
	{
		// Limbs i and i + 8 of the operand of a square, as WriteOperands writes them for both sides, and doubled.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void WriteSquareOperands(ref Vector128<ulong> operands, ref Vector128<ulong> doubled, nint i, Vector128<ulong> low, Vector128<ulong> high)
		{
			WriteOperands(ref operands, i, low, high, low, high);
			Unsafe.Add(ref doubled, i) = low + low;
			Unsafe.Add(ref doubled, i + 8) = high + high;
			Unsafe.Add(ref doubled, i + 16) = low + high << 1;
		}
	}
}
