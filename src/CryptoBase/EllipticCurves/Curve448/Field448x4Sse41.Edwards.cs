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
			Pair.PrepareRight(ref operands, i, DiffSum(Unsafe.Add(ref ab, i), Vector128.Create(TwoP)), DiffSum(Unsafe.Add(ref ab, i + 8), twoPHigh));
			Pair.PrepareRight(ref second, i, Unsafe.Add(ref cd, i), Unsafe.Add(ref cd, i + 8));
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
			Pair.WriteOperands(ref operands, i, leftLowAB, leftHighAB, rightLowAB, rightHighAB);
			Pair.WriteOperands(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
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
		Pair.SquareProduct(ref operands, ref doubled, ref products);
		Pair.SquareProduct(ref second, ref Unsafe.Add(ref doubled, DoubledLength), ref productsCD);
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

		Pair.CarryLeft(ref operands);
		Pair.CarryLeft(ref second);
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
			Pair.PrepareRight(ref operands, i, low, high);
			Pair.PrepareRight(ref second, i, Previous(Unsafe.Add(ref cd, i), low + Swap(low)), Previous(Unsafe.Add(ref cd, i + 8), high + Swap(high)));
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

		Pair.CarryLeft(ref operands);
		Pair.CarryLeft(ref second);
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
		Pair.SquareProduct(ref operands, ref doubled, ref products);
		Pair.SquareProduct(ref second, ref Unsafe.Add(ref doubled, DoubledLength), ref productsCD);
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

		Pair.CarryLeft(ref operands);
		Pair.CarryLeft(ref second);
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

	// Limbs i, i + 1, i + 8 and i + 9 of the left operand and the sums of its halves from a 56-bit limb of the low half and the one of the high half, each lane where negate is set taken from 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntryLimbs(ref Vector128<ulong> operands, nint i, Vector128<ulong> low, Vector128<ulong> high, Vector128<ulong> negate)
	{
		Vector128<ulong> mask = Vector128.Create(Mask);
		Vector128<ulong> twoP = Vector128.Create(TwoP);
		Vector128<ulong> limb0 = NegateUnder(low & mask, twoP, negate);
		Vector128<ulong> limb1 = NegateUnder(low >> Bits, twoP, negate);
		Vector128<ulong> limb8 = NegateUnder(high & mask, Vector128.Create(i is 0 ? TwoP8 : TwoP), negate);
		Vector128<ulong> limb9 = NegateUnder(high >> Bits, twoP, negate);
		ref Vector128<ulong> left = ref Unsafe.Add(ref operands, Left + i);
		left = limb0;
		Unsafe.Add(ref left, 1) = limb1;
		Unsafe.Add(ref left, 8) = limb8;
		Unsafe.Add(ref left, 9) = limb9;
		ref Vector128<ulong> sums = ref Unsafe.Add(ref operands, Sums + i);
		sums = limb0 + limb8;
		Unsafe.Add(ref sums, 1) = limb1 + limb9;
	}

	// Limbs i and i + 8 of the left operand, to be carried, and of the right one.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteUncarried(ref Vector128<ulong> operands, nint i, Vector128<ulong> leftLow, Vector128<ulong> leftHigh, Vector128<ulong> rightLow, Vector128<ulong> rightHigh)
	{
		Unsafe.Add(ref operands, Left + i) = leftLow;
		Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
		Pair.PrepareRight(ref operands, i, rightLow, rightHigh);
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

	// value, or 2p − value where negate is set: (value ^ m) + (m & (2p + 1)) is 2p − value modulo 2^64 for m all ones.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> NegateUnder(Vector128<ulong> value, Vector128<ulong> twoP, Vector128<ulong> negate)
	{
		return (value ^ negate) + (negate & twoP + Vector128<ulong>.One);
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

		// As Field448x4Avx2.SquareProduct on two lanes, with the doubled operand at doubled.
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void SquareProduct(ref Vector128<ulong> operands, ref Vector128<ulong> doubled, ref Vector128<ulong> result)
		{
			ref Vector128<ulong> x = ref Unsafe.Add(ref operands, Left);
			ref Vector128<ulong> d = ref doubled;
			ref Vector128<ulong> y = ref Unsafe.Add(ref operands, Right);
			Vector128<ulong> carryLow = Vector128<ulong>.Zero;
			Vector128<ulong> carryHigh = Vector128<ulong>.Zero;
			Vector128<ulong> p0 = Vector128<ulong>.Zero, q0 = Vector128<ulong>.Zero, r0 = Vector128<ulong>.Zero;
			Vector128<ulong> p1 = Vector128<ulong>.Zero, q1 = Vector128<ulong>.Zero, r1 = Vector128<ulong>.Zero;
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
			p0 = Vector128<ulong>.Zero;
			q0 = Vector128<ulong>.Zero;
			r0 = Vector128<ulong>.Zero;
			p1 = Vector128<ulong>.Zero;
			q1 = Vector128<ulong>.Zero;
			r1 = Vector128<ulong>.Zero;
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
			p0 = Vector128<ulong>.Zero;
			q0 = Vector128<ulong>.Zero;
			r0 = Vector128<ulong>.Zero;
			p1 = Vector128<ulong>.Zero;
			q1 = Vector128<ulong>.Zero;
			r1 = Vector128<ulong>.Zero;
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
			p0 = Vector128<ulong>.Zero;
			q0 = Vector128<ulong>.Zero;
			r0 = Vector128<ulong>.Zero;
			p1 = Vector128<ulong>.Zero;
			q1 = Vector128<ulong>.Zero;
			r1 = Vector128<ulong>.Zero;
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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Term(ref Vector128<ulong> x, nint k, ref Vector128<ulong> y, nint n, ref Vector128<ulong> p, ref Vector128<ulong> q, ref Vector128<ulong> r)
		{
			p += M(Unsafe.Add(ref x, k), Unsafe.Add(ref y, n + 16));
			q += M(Unsafe.Add(ref x, k + 8), Unsafe.Add(ref y, n + 8));
			r += M(Unsafe.Add(ref x, k + 16), Unsafe.Add(ref y, n));
		}
	}
}
