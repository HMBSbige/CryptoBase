using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.EllipticCurves.Curve448;

// The point formulas of Field448x4Avx2 in 32-bit lanes, which every operand fits: no lane of a formula exceeds 6·2^28 + 2^11 before the carry, and the doubled operand of a square, from lanes with m ≤ 2, stays below 2^31 + 2^12.
internal partial struct Field448x4AdvSimd : IEdwardsField448x4<Field448x4AdvSimd>
{
	private const uint ThreeP = 3 * Mask;
	private const uint ThreeP8 = 3 * (Mask - 1);

	// The left operand of a square doubled, after the products of a step, as SquareProduct takes it.
	private const int Doubled = 72;

	// As Field448x4Sse41.SelectBase: lanes (y − x, y + x, 2, 2d'xy), lane D negated where negative is set.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void SelectBase(int comb, uint index, ulong negative, ref Field448x4AdvSimd scratch)
	{
		TwistedBaseTable.SelectPacked(comb, index, negative, out Vector128<ulong> plus0, out Vector128<ulong> plus1, out Vector128<ulong> plus2, out Vector128<ulong> plus3, out Vector128<ulong> minus0, out Vector128<ulong> minus1, out Vector128<ulong> minus2, out Vector128<ulong> minus3, out Vector128<ulong> product0, out Vector128<ulong> product1, out Vector128<ulong> product2, out Vector128<ulong> product3);
		Vector128<uint> negate = Vector128.Create(0, 0, 0, (uint)negative);
		WriteEntryPairs(ref scratch.L0, 0, minus0, plus0, Vector128.CreateScalar(2UL), product0, minus2, plus2, Vector128<ulong>.Zero, product2, negate);
		WriteEntryPairs(ref scratch.L0, 4, minus1, plus1, Vector128<ulong>.Zero, product1, minus3, plus3, Vector128<ulong>.Zero, product3, negate);
	}

	// As Field448x4Sse41.LoadAffine.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LoadAffine(in EdwardsAffinePoint point, bool negative, ref Field448x4AdvSimd scratch)
	{
		Field448 x = point.X;
		Field448 product = point.DXY;

		if (negative)
		{
			Field448.Negate(in x, out x);
			Field448.Negate(in product, out product);
		}

		Field448.Add(in x, in point.Y, out Field448 sum);
		WriteEntry(ref scratch.L0, in x, in point.Y, in product, in sum);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedAdd(ref Field448x4AdvSimd point, ref Field448x4AdvSimd scratch)
	{
		ref Vector128<uint> operands = ref scratch.L0;
		ref Vector128<uint> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<uint> limbs = ref point.L0;
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareRight(ref operands, i, DiffSum(Unsafe.Add(ref limbs, i), Vector128.Create(TwoP)), DiffSum(Unsafe.Add(ref limbs, i + 8), twoPHigh));
			twoPHigh = Vector128.Create(TwoP);
		}

		Product(ref operands, ref products);
		twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedAdd(Unsafe.Add(ref products, i), Vector128.Create(TwoP), out Vector128<uint> leftLow, out Vector128<uint> rightLow);
			FinishTwistedAdd(Unsafe.Add(ref products, i + 8), twoPHigh, out Vector128<uint> leftHigh, out Vector128<uint> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			Unsafe.Add(ref operands, Sums + i) = leftLow + leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			twoPHigh = Vector128.Create(TwoP);
		}

		Product(ref operands, ref limbs);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void TwistedDouble(ref Field448x4AdvSimd point, ref Field448x4AdvSimd scratch)
	{
		ref Vector128<uint> operands = ref scratch.L0;
		ref Vector128<uint> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(ref point.L0, ref operands);
		SquareProduct(ref operands, ref products);
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);
		Vector128<uint> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishTwistedDouble(Unsafe.Add(ref products, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<uint> leftLow, out Vector128<uint> rightLow);
			FinishTwistedDouble(Unsafe.Add(ref products, i + 8), twoPHigh, threePHigh, out Vector128<uint> leftHigh, out Vector128<uint> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref point.L0);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Add(ref Field448x4AdvSimd point, ref Field448x4AdvSimd scratch)
	{
		ref Vector128<uint> operands = ref scratch.L0;
		ref Vector128<uint> products = ref Unsafe.Add(ref operands, Products);
		ref Vector128<uint> limbs = ref point.L0;

		for (nint i = 0; i < 8; ++i)
		{
			PrepareRight(ref operands, i, AddOperand(Unsafe.Add(ref limbs, i)), AddOperand(Unsafe.Add(ref limbs, i + 8)));
		}

		Product(ref operands, ref products);
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);
		Vector128<uint> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishAdd(Unsafe.Add(ref products, i), Unsafe.Add(ref limbs, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<uint> leftLow, out Vector128<uint> rightLow);
			FinishAdd(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref limbs, i + 8), twoPHigh, threePHigh, out Vector128<uint> leftHigh, out Vector128<uint> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref limbs);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Double(ref Field448x4AdvSimd point, ref Field448x4AdvSimd scratch)
	{
		ref Vector128<uint> operands = ref scratch.L0;
		ref Vector128<uint> products = ref Unsafe.Add(ref operands, Products);
		PrepareDouble(ref point.L0, ref operands);
		SquareProduct(ref operands, ref products);
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);
		Vector128<uint> threePHigh = Vector128.Create(ThreeP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishDouble(Unsafe.Add(ref products, i), Vector128.Create(TwoP), Vector128.Create(ThreeP), out Vector128<uint> leftLow, out Vector128<uint> rightLow);
			FinishDouble(Unsafe.Add(ref products, i + 8), twoPHigh, threePHigh, out Vector128<uint> leftHigh, out Vector128<uint> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			twoPHigh = Vector128.Create(TwoP);
			threePHigh = Vector128.Create(ThreeP);
		}

		CarryLeft(ref operands);
		Product(ref operands, ref point.L0);
	}

	// The product of (X, Y, Z, X + Y) by itself.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(ref Vector128<uint> limbs, ref Vector128<uint> operands)
	{
		for (nint i = 0; i < 8; ++i)
		{
			WriteSquareOperands(ref operands, i, SquareOperand(Unsafe.Add(ref limbs, i)), SquareOperand(Unsafe.Add(ref limbs, i + 8)));
		}
	}

	// Limbs i and i + 8 of the operand of a square on both sides, as Product takes them, and doubled.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteSquareOperands(ref Vector128<uint> operands, nint i, Vector128<uint> low, Vector128<uint> high)
	{
		ref Vector128<uint> doubled = ref Unsafe.Add(ref operands, Doubled);
		Unsafe.Add(ref operands, Left + i) = low;
		Unsafe.Add(ref operands, Left + i + 8) = high;
		Unsafe.Add(ref operands, Sums + i) = low + high;
		PrepareRight(ref operands, i, low, high);
		Unsafe.Add(ref doubled, i) = low + low;
		Unsafe.Add(ref doubled, i + 8) = high + high;
		Unsafe.Add(ref doubled, i + 16) = low + high << 1;
	}

	// As Field448x4Avx2.SquareProduct, two columns at a time as Product takes them, lanes A and B and lanes C and D by umlal into separate columns.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SquareProduct(ref Vector128<uint> operands, ref Vector128<uint> result)
	{
		ref Vector64<uint> x = ref Halves(ref Unsafe.Add(ref operands, Left));
		ref Vector64<uint> d = ref Halves(ref Unsafe.Add(ref operands, Doubled));
		ref Vector64<uint> y = ref Halves(ref Unsafe.Add(ref operands, Right));
		Vector128<ulong> carryLow = Vector128<ulong>.Zero;
		Vector128<ulong> carryLowUpper = Vector128<ulong>.Zero;
		Vector128<ulong> carryHigh = Vector128<ulong>.Zero;
		Vector128<ulong> carryHighUpper = Vector128<ulong>.Zero;
		Accumulators first = default;
		Accumulators second = default;

		Term(ref x, 0, ref y, 8, ref first);
		Term(ref d, 0, ref y, 9, ref second);
		Term(ref d, 1, ref y, 7, ref first);
		Term(ref d, 2, ref y, 6, ref first);
		Term(ref d, 2, ref y, 7, ref second);
		Term(ref d, 3, ref y, 5, ref first);
		Term(ref d, 3, ref y, 6, ref second);
		Term(ref x, 4, ref y, 4, ref first);
		Term(ref d, 4, ref y, 5, ref second);
		Columns(ref result, 0, ref first, ref second, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		Term(ref d, 0, ref y, 10, ref first);
		Term(ref d, 0, ref y, 11, ref second);
		Term(ref x, 1, ref y, 9, ref first);
		Term(ref d, 1, ref y, 10, ref second);
		Term(ref d, 3, ref y, 7, ref first);
		Term(ref d, 4, ref y, 6, ref first);
		Term(ref d, 4, ref y, 7, ref second);
		Term(ref x, 5, ref y, 5, ref first);
		Term(ref d, 5, ref y, 6, ref second);
		Columns(ref result, 2, ref first, ref second, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		Term(ref d, 0, ref y, 12, ref first);
		Term(ref d, 0, ref y, 13, ref second);
		Term(ref d, 1, ref y, 11, ref first);
		Term(ref d, 1, ref y, 12, ref second);
		Term(ref x, 2, ref y, 10, ref first);
		Term(ref d, 2, ref y, 11, ref second);
		Term(ref d, 5, ref y, 7, ref first);
		Term(ref x, 6, ref y, 6, ref first);
		Term(ref d, 6, ref y, 7, ref second);
		Columns(ref result, 4, ref first, ref second, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		Term(ref d, 0, ref y, 14, ref first);
		Term(ref d, 0, ref y, 15, ref second);
		Term(ref d, 1, ref y, 13, ref first);
		Term(ref d, 1, ref y, 14, ref second);
		Term(ref d, 2, ref y, 12, ref first);
		Term(ref d, 2, ref y, 13, ref second);
		Term(ref x, 3, ref y, 11, ref first);
		Term(ref d, 3, ref y, 12, ref second);
		Term(ref x, 7, ref y, 7, ref first);
		Columns(ref result, 6, ref first, ref second, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		Wrap(ref result, carryLow, carryLowUpper, carryHigh, carryHighUpper);
	}

	// x_k, of the operand or of its double, times sum_n, high_n and low_n of the right operand, both pairs of lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Term(ref Vector64<uint> x, nint k, ref Vector64<uint> y, nint n, ref Accumulators sums)
	{
		sums.P = AdvSimd.MultiplyWideningLowerAndAdd(sums.P, Unsafe.Add(ref x, 2 * k), Unsafe.Add(ref y, 2 * n + 32));
		sums.PUpper = AdvSimd.MultiplyWideningLowerAndAdd(sums.PUpper, Unsafe.Add(ref x, 2 * k + 1), Unsafe.Add(ref y, 2 * n + 33));
		sums.Q = AdvSimd.MultiplyWideningLowerAndAdd(sums.Q, Unsafe.Add(ref x, 2 * k + 16), Unsafe.Add(ref y, 2 * n + 16));
		sums.QUpper = AdvSimd.MultiplyWideningLowerAndAdd(sums.QUpper, Unsafe.Add(ref x, 2 * k + 17), Unsafe.Add(ref y, 2 * n + 17));
		sums.R = AdvSimd.MultiplyWideningLowerAndAdd(sums.R, Unsafe.Add(ref x, 2 * k + 32), Unsafe.Add(ref y, 2 * n));
		sums.RUpper = AdvSimd.MultiplyWideningLowerAndAdd(sums.RUpper, Unsafe.Add(ref x, 2 * k + 33), Unsafe.Add(ref y, 2 * n + 1));
	}

	// Limbs j, j + 1, j + 8 and j + 9 from the sums of columns j and j + 1, which then start again from zero.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Columns(ref Vector128<uint> result, nint j, ref Accumulators first, ref Accumulators second, ref Vector128<ulong> carryLow, ref Vector128<ulong> carryLowUpper, ref Vector128<ulong> carryHigh, ref Vector128<ulong> carryHighUpper)
	{
		Column(ref result, j, first.P + first.Q, first.PUpper + first.QUpper, first.R - first.P, first.RUpper - first.PUpper, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		Column(ref result, j + 1, second.P + second.Q, second.PUpper + second.QUpper, second.R - second.P, second.RUpper - second.PUpper, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		first = default;
		second = default;
	}

	// The sums of P, Q and R of one column, lanes A and B and their upper counterparts of lanes C and D.
	private struct Accumulators
	{
		internal Vector128<ulong> P;
		internal Vector128<ulong> PUpper;
		internal Vector128<ulong> Q;
		internal Vector128<ulong> QUpper;
		internal Vector128<ulong> R;
		internal Vector128<ulong> RUpper;
	}

	// The left operand of an addition from lanes (a, b, c, d): the 56-bit limbs k of the four, for k below 4, make limbs 2k and 2k + 1, and limbs k + 4 make limbs 2k + 8 and 2k + 9, each narrowed from pairs of lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntry(ref Vector128<uint> operands, in Field448 a, in Field448 b, in Field448 c, in Field448 d)
	{
		ref ulong la = ref Unsafe.AsRef(in a.L0);
		ref ulong lb = ref Unsafe.AsRef(in b.L0);
		ref ulong lc = ref Unsafe.AsRef(in c.L0);
		ref ulong ld = ref Unsafe.AsRef(in d.L0);

		for (nint k = 0; k < 4; k += 2)
		{
			Vector128<ulong> lowA = Vector128.LoadUnsafe(ref la, (nuint)k);
			Vector128<ulong> lowB = Vector128.LoadUnsafe(ref lb, (nuint)k);
			Vector128<ulong> lowC = Vector128.LoadUnsafe(ref lc, (nuint)k);
			Vector128<ulong> lowD = Vector128.LoadUnsafe(ref ld, (nuint)k);
			Vector128<ulong> highA = Vector128.LoadUnsafe(ref la, (nuint)k + 4);
			Vector128<ulong> highB = Vector128.LoadUnsafe(ref lb, (nuint)k + 4);
			Vector128<ulong> highC = Vector128.LoadUnsafe(ref lc, (nuint)k + 4);
			Vector128<ulong> highD = Vector128.LoadUnsafe(ref ld, (nuint)k + 4);
			WriteEntryPairs(ref operands, 2 * k, lowA, lowB, lowC, lowD, highA, highB, highC, highD, Vector128<uint>.Zero);
		}
	}

	// Limbs i to i + 3 and i + 8 to i + 11 from lanes a, b, c and d of two 56-bit limbs of the low half and of the two 4 above them, lane D taken from 2p where negate is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntryPairs(ref Vector128<uint> operands, nint i, Vector128<ulong> aLow, Vector128<ulong> bLow, Vector128<ulong> cLow, Vector128<ulong> dLow, Vector128<ulong> aHigh, Vector128<ulong> bHigh, Vector128<ulong> cHigh, Vector128<ulong> dHigh, Vector128<uint> negate)
	{
		WriteEntryLimbs(ref operands, i, AdvSimd.Arm64.ZipLow(aLow, bLow), AdvSimd.Arm64.ZipLow(cLow, dLow), AdvSimd.Arm64.ZipLow(aHigh, bHigh), AdvSimd.Arm64.ZipLow(cHigh, dHigh), negate);
		WriteEntryLimbs(ref operands, i + 2, AdvSimd.Arm64.ZipHigh(aLow, bLow), AdvSimd.Arm64.ZipHigh(cLow, dLow), AdvSimd.Arm64.ZipHigh(aHigh, bHigh), AdvSimd.Arm64.ZipHigh(cHigh, dHigh), negate);
	}

	// Limbs i, i + 1, i + 8 and i + 9 from 56-bit limbs of lanes A and B and of lanes C and D, of the low half and of the high half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteEntryLimbs(ref Vector128<uint> operands, nint i, Vector128<ulong> lowAB, Vector128<ulong> lowCD, Vector128<ulong> highAB, Vector128<ulong> highCD, Vector128<uint> negate)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		Vector128<uint> twoP = Vector128.Create(TwoP);
		Vector128<uint> limb0 = NegateUnder(Vector128.Narrow(lowAB & mask, lowCD & mask), twoP, negate);
		Vector128<uint> limb1 = NegateUnder(Vector128.Narrow(lowAB >> Bits, lowCD >> Bits), twoP, negate);
		Vector128<uint> limb8 = NegateUnder(Vector128.Narrow(highAB & mask, highCD & mask), Vector128.Create(i is 0 ? TwoP8 : TwoP), negate);
		Vector128<uint> limb9 = NegateUnder(Vector128.Narrow(highAB >> Bits, highCD >> Bits), twoP, negate);
		ref Vector128<uint> left = ref Unsafe.Add(ref operands, Left + i);
		left = limb0;
		Unsafe.Add(ref left, 1) = limb1;
		Unsafe.Add(ref left, 8) = limb8;
		Unsafe.Add(ref left, 9) = limb9;
		ref Vector128<uint> sums = ref Unsafe.Add(ref operands, Sums + i);
		sums = limb0 + limb8;
		Unsafe.Add(ref sums, 1) = limb1 + limb9;
	}

	// As Field448x4Avx2.CarryLeft, in 32-bit lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryLeft(ref Vector128<uint> operands)
	{
		Vector128<uint> mask = Vector128.Create(Mask);
		ref Vector128<uint> left = ref Unsafe.Add(ref operands, Left);
		Vector128<uint> carryLow = Unsafe.Add(ref left, 15) >> Bits;
		Vector128<uint> carryHigh = (Unsafe.Add(ref left, 7) >> Bits) + carryLow;

		for (nint i = 0; i < 8; ++i)
		{
			Vector128<uint> low = Unsafe.Add(ref left, i);
			Vector128<uint> high = Unsafe.Add(ref left, i + 8);
			Vector128<uint> carriedLow = (low & mask) + carryLow;
			Vector128<uint> carriedHigh = (high & mask) + carryHigh;
			Unsafe.Add(ref left, i) = carriedLow;
			Unsafe.Add(ref left, i + 8) = carriedHigh;
			Unsafe.Add(ref operands, Sums + i) = carriedLow + carriedHigh;
			carryLow = low >> Bits;
			carryHigh = high >> Bits;
		}
	}

	// (B, A, D, C).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Swap(Vector128<uint> limb)
	{
		return AdvSimd.ReverseElement32(limb.AsUInt64()).AsUInt32();
	}

	// Lane k in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Broadcast(Vector128<uint> limb, [ConstantExpected(Max = (byte)3)] byte k)
	{
		return AdvSimd.DuplicateSelectedScalarToVector128(limb, k);
	}

	// All ones in the lanes A to D whose bits 0 to 3 lanes sets.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> Lanes(byte lanes)
	{
		return Vector128.Create((lanes & 1) is 0 ? 0 : uint.MaxValue, (lanes & 2) is 0 ? 0 : uint.MaxValue, (lanes & 4) is 0 ? 0 : uint.MaxValue, (lanes & 8) is 0 ? 0 : uint.MaxValue);
	}

	// (X − Y, X + Y, Z, T) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> DiffSum(Vector128<uint> limb, Vector128<uint> twoP)
	{
		Vector128<uint> swapped = Swap(limb);
		return Vector128.ConditionalSelect(Lanes(0b1100), limb, limb + Vector128.ConditionalSelect(Lanes(0b0010), swapped, twoP - swapped));
	}

	// (X, Y, T, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> AddOperand(Vector128<uint> limb)
	{
		Vector128<uint> abda = AdvSimd.Arm64.VectorTableLookup(limb.AsByte(), Vector128.Create((byte)0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3)).AsUInt32();
		return abda + (Broadcast(limb, 1) & Lanes(0b1000));
	}

	// (X, Y, Z, X + Y) from (X, Y, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> SquareOperand(Vector128<uint> limb)
	{
		return Vector128.ConditionalSelect(Lanes(0b1000), Broadcast(limb, 0) + Broadcast(limb, 1), limb);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedAdd(Vector128<uint> limb, Vector128<uint> twoP, out Vector128<uint> left, out Vector128<uint> right)
	{
		Vector128<uint> swapped = Swap(limb);
		Vector128<uint> sums = limb + swapped;
		Vector128<uint> differences = swapped + twoP - limb;
		Vector128<byte> eegf = Vector128.ConditionalSelect(Lanes(0b1000), differences, sums).AsByte();
		Vector128<byte> hegf = Vector128.ConditionalSelect(Lanes(0b1001), differences, sums).AsByte();
		left = AdvSimd.Arm64.VectorTableLookup(eegf, Vector128.Create((byte)0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3)).AsUInt32();
		right = AdvSimd.Arm64.VectorTableLookup(hegf, Vector128.Create((byte)12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11, 0, 1, 2, 3)).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishTwistedDouble(Vector128<uint> limb, Vector128<uint> twoP, Vector128<uint> threeP, out Vector128<uint> left, out Vector128<uint> right)
	{
		Vector128<uint> xx = Broadcast(limb, 0);
		Vector128<uint> yy = Broadcast(limb, 1);
		Vector128<uint> zz = Broadcast(limb, 2);
		Vector128<uint> h = xx + yy;
		Vector128<uint> e = Broadcast(limb, 3) + threeP - h;
		Vector128<uint> g = yy + twoP - xx;
		Vector128<uint> f = zz + zz + xx + twoP - yy;
		left = Vector128.ConditionalSelect(Lanes(0b0100), f, Vector128.ConditionalSelect(Lanes(0b0010), g, e));
		right = Vector128.ConditionalSelect(Lanes(0b0100), g, Vector128.ConditionalSelect(Lanes(0b1010), h, f));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector128<uint> limb, Vector128<uint> point, Vector128<uint> twoP, Vector128<uint> threeP, out Vector128<uint> left, out Vector128<uint> right)
	{
		Vector128<uint> a = Broadcast(limb, 0);
		Vector128<uint> b = Broadcast(limb, 1);
		Vector128<uint> c = Broadcast(limb, 2);
		Vector128<uint> z = Broadcast(point, 2);
		Vector128<uint> e = Broadcast(limb, 3) + threeP - (a + b);
		Vector128<uint> f = z + twoP - c;
		Vector128<uint> g = z + c;
		Vector128<uint> h = b + twoP - a;
		left = Vector128.ConditionalSelect(Lanes(0b0100), f, Vector128.ConditionalSelect(Lanes(0b0010), g, e));
		right = Vector128.ConditionalSelect(Lanes(0b0100), g, Vector128.ConditionalSelect(Lanes(0b1010), h, f));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector128<uint> limb, Vector128<uint> twoP, Vector128<uint> threeP, out Vector128<uint> left, out Vector128<uint> right)
	{
		Vector128<uint> xx = Broadcast(limb, 0);
		Vector128<uint> yy = Broadcast(limb, 1);
		Vector128<uint> zz = Broadcast(limb, 2);
		Vector128<uint> sum = xx + yy;
		Vector128<uint> x = Broadcast(limb, 3) + threeP - sum;
		Vector128<uint> y = yy + twoP - xx;
		Vector128<uint> t = zz + zz + threeP - sum;
		left = Vector128.ConditionalSelect(Lanes(0b0100), sum, Vector128.ConditionalSelect(Lanes(0b0010), y, x));
		right = Vector128.ConditionalSelect(Lanes(0b1000), y, Vector128.ConditionalSelect(Lanes(0b0010), sum, t));
	}

	// value, or 2p − value where negate is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> NegateUnder(Vector128<uint> value, Vector128<uint> twoP, Vector128<uint> negate)
	{
		return (value ^ negate) + (negate & twoP + Vector128<uint>.One);
	}
}
