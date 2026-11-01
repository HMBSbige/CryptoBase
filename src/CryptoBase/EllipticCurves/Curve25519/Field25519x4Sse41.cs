using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.EllipticCurves.Curve25519;

// The limbs of Field25519x4Avx2 in 128-bit vectors, lanes A and B in one pair of ten and lanes C and D in another, with the same bounds. A product is two products of two lanes, each gathered row by row as in Field25519x4Avx2.Multiply.
// Any result may be the same variable as an input: each member reads a limb of its inputs before it writes that limb of a result.
internal struct Field25519x4Sse41 : IField25519x4<Field25519x4Sse41>
{
	internal Pair AB;
	internal Pair CD;

	private const ulong Mask25 = (1UL << 25) - 1;
	private const ulong Mask26 = (1UL << 26) - 1;

	private const ulong TwoP0 = (1UL << 27) - 38;
	private const ulong TwoPEven = (1UL << 27) - 2;
	private const ulong TwoPOdd = (1UL << 26) - 2;

	private const ulong P37Limb0 = (1UL << 26) - 19 << 37;
	private const ulong P37Even = (1UL << 26) - 1 << 37;
	private const ulong P37Odd = (1UL << 25) - 1 << 37;

	// pblendw mask of the second 64-bit lane.
	private const byte Second = 0xF0;

	// pshufd control that swaps the two 64-bit lanes.
	private const byte SwapLanes = 0b01_00_11_10;

	public static bool IsSupported => Sse41.IsSupported;

	public static void Create(in Field25519 a, in Field25519 b, in Field25519 c, in Field25519 d, out Field25519x4Sse41 result)
	{
		Pair.Create(in a, in b, out result.AB);
		Pair.Create(in c, in d, out result.CD);
	}

	public static void Extract(in Field25519x4Sse41 value, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d)
	{
		Pair.Extract(in value.AB, out a, out b);
		Pair.Extract(in value.CD, out c, out d);
	}

	public static void Multiply(in Field25519x4Sse41 left, in Field25519x4Sse41 right, out Field25519x4Sse41 result)
	{
		Unsafe.SkipInit(out Pair ab);
		Pair.Multiply(in left.AB, in right.AB, out ab);
		Pair.Multiply(in left.CD, in right.CD, out result.CD);
		result.AB = ab;
	}

	private static void SquareAndNegateD(in Field25519x4Sse41 value, out Field25519x4Sse41 result)
	{
		Unsafe.SkipInit(out Pair ab);
		Pair.Square(in value.AB, false, out ab);
		Pair.Square(in value.CD, true, out result.CD);
		result.AB = ab;
	}

	public static void MultiplySmall(in Field25519x4Sse41 value, uint a, uint b, uint c, uint d, out Field25519x4Sse41 result)
	{
		Pair.MultiplySmall(in value.AB, Vector128.Create((ulong)a, b), out result.AB);
		Pair.MultiplySmall(in value.CD, Vector128.Create((ulong)c, d), out result.CD);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Add(in Field25519x4Sse41 left, in Field25519x4Sse41 right, out Field25519x4Sse41 result)
	{
		Pair.Add(in left.AB, in right.AB, out result.AB);
		Pair.Add(in left.CD, in right.CD, out result.CD);
	}

	// 2p − D in the second lane of CD.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void NegateD(in Field25519x4Sse41 value, out Field25519x4Sse41 result)
	{
		result.AB = value.AB;
		result.CD.L0 = NegateSecond(value.CD.L0, TwoP0);
		result.CD.L1 = NegateSecond(value.CD.L1, TwoPOdd);
		result.CD.L2 = NegateSecond(value.CD.L2, TwoPEven);
		result.CD.L3 = NegateSecond(value.CD.L3, TwoPOdd);
		result.CD.L4 = NegateSecond(value.CD.L4, TwoPEven);
		result.CD.L5 = NegateSecond(value.CD.L5, TwoPOdd);
		result.CD.L6 = NegateSecond(value.CD.L6, TwoPEven);
		result.CD.L7 = NegateSecond(value.CD.L7, TwoPOdd);
		result.CD.L8 = NegateSecond(value.CD.L8, TwoPEven);
		result.CD.L9 = NegateSecond(value.CD.L9, TwoPOdd);
	}

	// (B, A) and (C, 2p − D).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void NegateCached(in Field25519x4Sse41 value, out Field25519x4Sse41 result)
	{
		NegateD(in value, out result);
		result.AB.L0 = Swap(result.AB.L0);
		result.AB.L1 = Swap(result.AB.L1);
		result.AB.L2 = Swap(result.AB.L2);
		result.AB.L3 = Swap(result.AB.L3);
		result.AB.L4 = Swap(result.AB.L4);
		result.AB.L5 = Swap(result.AB.L5);
		result.AB.L6 = Swap(result.AB.L6);
		result.AB.L7 = Swap(result.AB.L7);
		result.AB.L8 = Swap(result.AB.L8);
		result.AB.L9 = Swap(result.AB.L9);
	}

	// CD becomes (Z, X + Y).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(in Field25519x4Sse41 point, out Field25519x4Sse41 result)
	{
		result.CD.L0 = PrepareDouble(point.AB.L0, point.CD.L0);
		result.CD.L1 = PrepareDouble(point.AB.L1, point.CD.L1);
		result.CD.L2 = PrepareDouble(point.AB.L2, point.CD.L2);
		result.CD.L3 = PrepareDouble(point.AB.L3, point.CD.L3);
		result.CD.L4 = PrepareDouble(point.AB.L4, point.CD.L4);
		result.CD.L5 = PrepareDouble(point.AB.L5, point.CD.L5);
		result.CD.L6 = PrepareDouble(point.AB.L6, point.CD.L6);
		result.CD.L7 = PrepareDouble(point.AB.L7, point.CD.L7);
		result.CD.L8 = PrepareDouble(point.AB.L8, point.CD.L8);
		result.CD.L9 = PrepareDouble(point.AB.L9, point.CD.L9);
		result.AB = point.AB;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(in Field25519x4Sse41 squares, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		FinishDouble(squares.AB.L0, squares.CD.L0, TwoP0, out left.AB.L0, out left.CD.L0, out right.AB.L0, out right.CD.L0);
		FinishDouble(squares.AB.L1, squares.CD.L1, TwoPOdd, out left.AB.L1, out left.CD.L1, out right.AB.L1, out right.CD.L1);
		FinishDouble(squares.AB.L2, squares.CD.L2, TwoPEven, out left.AB.L2, out left.CD.L2, out right.AB.L2, out right.CD.L2);
		FinishDouble(squares.AB.L3, squares.CD.L3, TwoPOdd, out left.AB.L3, out left.CD.L3, out right.AB.L3, out right.CD.L3);
		FinishDouble(squares.AB.L4, squares.CD.L4, TwoPEven, out left.AB.L4, out left.CD.L4, out right.AB.L4, out right.CD.L4);
		FinishDouble(squares.AB.L5, squares.CD.L5, TwoPOdd, out left.AB.L5, out left.CD.L5, out right.AB.L5, out right.CD.L5);
		FinishDouble(squares.AB.L6, squares.CD.L6, TwoPEven, out left.AB.L6, out left.CD.L6, out right.AB.L6, out right.CD.L6);
		FinishDouble(squares.AB.L7, squares.CD.L7, TwoPOdd, out left.AB.L7, out left.CD.L7, out right.AB.L7, out right.CD.L7);
		FinishDouble(squares.AB.L8, squares.CD.L8, TwoPEven, out left.AB.L8, out left.CD.L8, out right.AB.L8, out right.CD.L8);
		FinishDouble(squares.AB.L9, squares.CD.L9, TwoPOdd, out left.AB.L9, out left.CD.L9, out right.AB.L9, out right.CD.L9);
	}

	// AB becomes (Y − X, Y + X).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DiffSum(in Field25519x4Sse41 point, out Field25519x4Sse41 result)
	{
		result.CD = point.CD;
		result.AB.L0 = DiffSum(point.AB.L0, TwoP0);
		result.AB.L1 = DiffSum(point.AB.L1, TwoPOdd);
		result.AB.L2 = DiffSum(point.AB.L2, TwoPEven);
		result.AB.L3 = DiffSum(point.AB.L3, TwoPOdd);
		result.AB.L4 = DiffSum(point.AB.L4, TwoPEven);
		result.AB.L5 = DiffSum(point.AB.L5, TwoPOdd);
		result.AB.L6 = DiffSum(point.AB.L6, TwoPEven);
		result.AB.L7 = DiffSum(point.AB.L7, TwoPOdd);
		result.AB.L8 = DiffSum(point.AB.L8, TwoPEven);
		result.AB.L9 = DiffSum(point.AB.L9, TwoPOdd);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(in Field25519x4Sse41 products, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		FinishAdd(products.AB.L0, products.CD.L0, TwoP0, out left.AB.L0, out left.CD.L0, out right.AB.L0, out right.CD.L0);
		FinishAdd(products.AB.L1, products.CD.L1, TwoPOdd, out left.AB.L1, out left.CD.L1, out right.AB.L1, out right.CD.L1);
		FinishAdd(products.AB.L2, products.CD.L2, TwoPEven, out left.AB.L2, out left.CD.L2, out right.AB.L2, out right.CD.L2);
		FinishAdd(products.AB.L3, products.CD.L3, TwoPOdd, out left.AB.L3, out left.CD.L3, out right.AB.L3, out right.CD.L3);
		FinishAdd(products.AB.L4, products.CD.L4, TwoPEven, out left.AB.L4, out left.CD.L4, out right.AB.L4, out right.CD.L4);
		FinishAdd(products.AB.L5, products.CD.L5, TwoPOdd, out left.AB.L5, out left.CD.L5, out right.AB.L5, out right.CD.L5);
		FinishAdd(products.AB.L6, products.CD.L6, TwoPEven, out left.AB.L6, out left.CD.L6, out right.AB.L6, out right.CD.L6);
		FinishAdd(products.AB.L7, products.CD.L7, TwoPOdd, out left.AB.L7, out left.CD.L7, out right.AB.L7, out right.CD.L7);
		FinishAdd(products.AB.L8, products.CD.L8, TwoPEven, out left.AB.L8, out left.CD.L8, out right.AB.L8, out right.CD.L8);
		FinishAdd(products.AB.L9, products.CD.L9, TwoPOdd, out left.AB.L9, out left.CD.L9, out right.AB.L9, out right.CD.L9);
	}

	// The swap exchanges the pairs under a mask.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(in Field25519x4Sse41 state, ulong swap, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		Vector128<ulong> mask = Vector128.Create(swap);
		PrepareLadder(state.AB.L0, state.CD.L0, mask, TwoP0, out left.AB.L0, out left.CD.L0, out right.AB.L0, out right.CD.L0);
		PrepareLadder(state.AB.L1, state.CD.L1, mask, TwoPOdd, out left.AB.L1, out left.CD.L1, out right.AB.L1, out right.CD.L1);
		PrepareLadder(state.AB.L2, state.CD.L2, mask, TwoPEven, out left.AB.L2, out left.CD.L2, out right.AB.L2, out right.CD.L2);
		PrepareLadder(state.AB.L3, state.CD.L3, mask, TwoPOdd, out left.AB.L3, out left.CD.L3, out right.AB.L3, out right.CD.L3);
		PrepareLadder(state.AB.L4, state.CD.L4, mask, TwoPEven, out left.AB.L4, out left.CD.L4, out right.AB.L4, out right.CD.L4);
		PrepareLadder(state.AB.L5, state.CD.L5, mask, TwoPOdd, out left.AB.L5, out left.CD.L5, out right.AB.L5, out right.CD.L5);
		PrepareLadder(state.AB.L6, state.CD.L6, mask, TwoPEven, out left.AB.L6, out left.CD.L6, out right.AB.L6, out right.CD.L6);
		PrepareLadder(state.AB.L7, state.CD.L7, mask, TwoPOdd, out left.AB.L7, out left.CD.L7, out right.AB.L7, out right.CD.L7);
		PrepareLadder(state.AB.L8, state.CD.L8, mask, TwoPEven, out left.AB.L8, out left.CD.L8, out right.AB.L8, out right.CD.L8);
		PrepareLadder(state.AB.L9, state.CD.L9, mask, TwoPOdd, out left.AB.L9, out left.CD.L9, out right.AB.L9, out right.CD.L9);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(in Field25519x4Sse41 products, out Field25519x4Sse41 left, out Field25519x4Sse41 right, out Field25519x4Sse41 difference)
	{
		FinishLadder(products.AB.L0, products.CD.L0, TwoP0, out left.AB.L0, out left.CD.L0, out right.AB.L0, out right.CD.L0, out difference.AB.L0, out difference.CD.L0);
		FinishLadder(products.AB.L1, products.CD.L1, TwoPOdd, out left.AB.L1, out left.CD.L1, out right.AB.L1, out right.CD.L1, out difference.AB.L1, out difference.CD.L1);
		FinishLadder(products.AB.L2, products.CD.L2, TwoPEven, out left.AB.L2, out left.CD.L2, out right.AB.L2, out right.CD.L2, out difference.AB.L2, out difference.CD.L2);
		FinishLadder(products.AB.L3, products.CD.L3, TwoPOdd, out left.AB.L3, out left.CD.L3, out right.AB.L3, out right.CD.L3, out difference.AB.L3, out difference.CD.L3);
		FinishLadder(products.AB.L4, products.CD.L4, TwoPEven, out left.AB.L4, out left.CD.L4, out right.AB.L4, out right.CD.L4, out difference.AB.L4, out difference.CD.L4);
		FinishLadder(products.AB.L5, products.CD.L5, TwoPOdd, out left.AB.L5, out left.CD.L5, out right.AB.L5, out right.CD.L5, out difference.AB.L5, out difference.CD.L5);
		FinishLadder(products.AB.L6, products.CD.L6, TwoPEven, out left.AB.L6, out left.CD.L6, out right.AB.L6, out right.CD.L6, out difference.AB.L6, out difference.CD.L6);
		FinishLadder(products.AB.L7, products.CD.L7, TwoPOdd, out left.AB.L7, out left.CD.L7, out right.AB.L7, out right.CD.L7, out difference.AB.L7, out difference.CD.L7);
		FinishLadder(products.AB.L8, products.CD.L8, TwoPEven, out left.AB.L8, out left.CD.L8, out right.AB.L8, out right.CD.L8, out difference.AB.L8, out difference.CD.L8);
		FinishLadder(products.AB.L9, products.CD.L9, TwoPOdd, out left.AB.L9, out left.CD.L9, out right.AB.L9, out right.CD.L9, out difference.AB.L9, out difference.CD.L9);
	}

	public static void AddOperands(in Field25519x4Sse41 point, in Field25519x4Sse41 cached, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		DiffSum(in point, out left);
		Multiply(in left, in cached, out right);
		FinishAdd(in right, out left, out right);
	}

	public static void DoubleOperands(in Field25519x4Sse41 point, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		PrepareDouble(in point, out left);
		SquareAndNegateD(in left, out left);
		FinishDouble(in left, out left, out right);
	}

	public static int MultiplierLength => 1;

	public static void CreateMultiplier(in Field25519 u, Span<Field25519x4Sse41> multiplier)
	{
		Create(in Field25519.One, in Field25519.One, in Field25519.One, in u, out multiplier[0]);
	}

	public static void LadderProducts(in Field25519x4Sse41 left, in Field25519x4Sse41 right, in Field25519x4Sse41 multiplier, out Field25519x4Sse41 result)
	{
		Multiply(in left, in right, out result);
		Multiply(in result, in multiplier, out result);
	}

	public static void LadderOperands(in Field25519x4Sse41 state, ulong swap, out Field25519x4Sse41 left, out Field25519x4Sse41 right)
	{
		PrepareLadder(in state, swap, out left, out right);
		Multiply(in left, in right, out Field25519x4Sse41 products);
		FinishLadder(in products, out left, out right, out Field25519x4Sse41 difference);
		MultiplySmall(in difference, 0, 121665, 0, 0, out difference);
		Add(in right, in difference, out right);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field25519x4Sse41 value)
	{
		Vector128<ulong> select = Vector128.Create(mask);
		SwapUnder(select, ref value.AB.L0, ref value.CD.L0);
		SwapUnder(select, ref value.AB.L1, ref value.CD.L1);
		SwapUnder(select, ref value.AB.L2, ref value.CD.L2);
		SwapUnder(select, ref value.AB.L3, ref value.CD.L3);
		SwapUnder(select, ref value.AB.L4, ref value.CD.L4);
		SwapUnder(select, ref value.AB.L5, ref value.CD.L5);
		SwapUnder(select, ref value.AB.L6, ref value.CD.L6);
		SwapUnder(select, ref value.AB.L7, ref value.CD.L7);
		SwapUnder(select, ref value.AB.L8, ref value.CD.L8);
		SwapUnder(select, ref value.AB.L9, ref value.CD.L9);
	}

	// (second, first).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Swap(Vector128<ulong> value)
	{
		return Sse2.Shuffle(value.AsUInt32(), SwapLanes).AsUInt64();
	}

	// The first lane of left and the second of right.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Blend(Vector128<ulong> left, Vector128<ulong> right)
	{
		return Sse41.Blend(left.AsUInt16(), right.AsUInt16(), Second).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> NegateSecond(Vector128<ulong> limbs, ulong twoP)
	{
		return Blend(limbs, Vector128.Create(twoP) - limbs);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SwapUnder(Vector128<ulong> mask, ref Vector128<ulong> first, ref Vector128<ulong> second)
	{
		Vector128<ulong> difference = (first ^ second) & mask;
		first ^= difference;
		second ^= difference;
	}

	// (Z, T) to (Z, X + Y).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> PrepareDouble(Vector128<ulong> xy, Vector128<ulong> zt)
	{
		return Blend(zt, xy + Swap(xy));
	}

	// (S1, S2) and (S3, −S4) to (S5, S6) = (S1, S1) + (S2, −S2) and (S8, S9) = (S1, S1) + (−S2, S2) + (2S3, −S4), then the operands (S8, S5, S8, S5) and (S9, S6, S6, S9).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector128<ulong> ab, Vector128<ulong> cd, ulong twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> s1 = Sse2.UnpackLow(ab, ab);
		Vector128<ulong> s2 = Sse2.UnpackHigh(ab, ab);
		Vector128<ulong> negated = Vector128.Create(twoP) - s2;
		Vector128<ulong> low = s1 + Blend(s2, negated);
		Vector128<ulong> high = s1 + Blend(negated, s2) + Blend(cd + cd, cd);
		leftAB = Sse2.UnpackLow(high, low);
		leftCD = leftAB;
		rightAB = Sse2.UnpackHigh(high, low);
		rightCD = Sse2.UnpackHigh(low, high);
	}

	// (X, Y) to (Y − X, Y + X).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> DiffSum(Vector128<ulong> limbs, ulong twoP)
	{
		Vector128<ulong> swapped = Swap(limbs);
		return Blend(swapped + Vector128.Create(twoP) - limbs, swapped + limbs);
	}

	// (S8, S9) to (S12, S13) and (S10, S11) to (S14, S15), then the operands (S12, S15, S15, S12) and (S14, S13, S14, S13).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector128<ulong> ab, Vector128<ulong> cd, ulong twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		Vector128<ulong> doubled = Vector128.Create(twoP);
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);
		Vector128<ulong> low = Blend(swappedAB + doubled - ab, swappedAB + ab);
		Vector128<ulong> high = Blend(cd + doubled - swappedCD, cd + swappedCD);
		leftAB = Blend(low, high);
		leftCD = Swap(leftAB);
		rightAB = Blend(high, low);
		rightCD = rightAB;
	}

	// (x2, z2) and (x3, z3), exchanged under the mask, to (A, B) = (x2 + z2, x2 − z2) and (C, D) = (x3 + z3, x3 − z3), then the operands (A, B, D, C) and (A, B, A, B).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> mask, ulong twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		SwapUnder(mask, ref ab, ref cd);
		Vector128<ulong> doubled = Vector128.Create(twoP);
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);
		Vector128<ulong> low = Sse2.UnpackLow(ab + swappedAB, ab + doubled - swappedAB);
		Vector128<ulong> high = Sse2.UnpackLow(cd + swappedCD, cd + doubled - swappedCD);
		leftAB = low;
		leftCD = Swap(high);
		rightAB = low;
		rightCD = low;
	}

	// (AA, BB) and (DA, CB) to the operands (AA, E, DA + CB, DA − CB) and (BB, AA, DA + CB, DA − CB), and (E, E, DA − CB, DA − CB).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector128<ulong> ab, Vector128<ulong> cd, ulong twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD, out Vector128<ulong> differenceAB, out Vector128<ulong> differenceCD)
	{
		Vector128<ulong> doubled = Vector128.Create(twoP);
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);
		Vector128<ulong> e = ab + doubled - swappedAB;
		Vector128<ulong> sumCD = cd + swappedCD;
		Vector128<ulong> differenceOfCD = cd + doubled - swappedCD;
		leftAB = Sse2.UnpackLow(ab, e);
		leftCD = Sse2.UnpackLow(sumCD, differenceOfCD);
		rightAB = swappedAB;
		rightCD = leftCD;
		differenceAB = Sse2.UnpackLow(e, e);
		differenceCD = Sse2.UnpackLow(differenceOfCD, differenceOfCD);
	}

	// Two of the four lanes: limb i of each in vector i.
	internal struct Pair
	{
		internal Vector128<ulong> L0;
		internal Vector128<ulong> L1;
		internal Vector128<ulong> L2;
		internal Vector128<ulong> L3;
		internal Vector128<ulong> L4;
		internal Vector128<ulong> L5;
		internal Vector128<ulong> L6;
		internal Vector128<ulong> L7;
		internal Vector128<ulong> L8;
		internal Vector128<ulong> L9;

		internal static void Create(in Field25519 a, in Field25519 b, out Pair result)
		{
			Vector128<ulong> mask26 = Vector128.Create(Mask26);
			Vector128<ulong> l0 = Vector128.Create(a.L0, b.L0);
			Vector128<ulong> l1 = Vector128.Create(a.L1, b.L1);
			Vector128<ulong> l2 = Vector128.Create(a.L2, b.L2);
			Vector128<ulong> l3 = Vector128.Create(a.L3, b.L3);
			Vector128<ulong> l4 = Vector128.Create(a.L4, b.L4);
			result.L0 = l0 & mask26;
			result.L1 = l0 >> 26;
			result.L2 = l1 & mask26;
			result.L3 = l1 >> 26;
			result.L4 = l2 & mask26;
			result.L5 = l2 >> 26;
			result.L6 = l3 & mask26;
			result.L7 = l3 >> 26;
			result.L8 = l4 & mask26;
			result.L9 = l4 >> 26;
		}

		internal static void Extract(in Pair value, out Field25519 a, out Field25519 b)
		{
			Vector128<ulong> l0 = value.L0 + (value.L1 << 26);
			Vector128<ulong> l1 = value.L2 + (value.L3 << 26);
			Vector128<ulong> l2 = value.L4 + (value.L5 << 26);
			Vector128<ulong> l3 = value.L6 + (value.L7 << 26);
			Vector128<ulong> l4 = value.L8 + (value.L9 << 26);
			Join(l0, l1, l2, l3, l4, 0, out a);
			Join(l0, l1, l2, l3, l4, 1, out b);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void Add(in Pair left, in Pair right, out Pair result)
		{
			result.L0 = left.L0 + right.L0;
			result.L1 = left.L1 + right.L1;
			result.L2 = left.L2 + right.L2;
			result.L3 = left.L3 + right.L3;
			result.L4 = left.L4 + right.L4;
			result.L5 = left.L5 + right.L5;
			result.L6 = left.L6 + right.L6;
			result.L7 = left.L7 + right.L7;
			result.L8 = left.L8 + right.L8;
			result.L9 = left.L9 + right.L9;
		}

		// The columns of Field25519x4Avx2.Multiply, with the same bounds, gathered row by row: limb j of the right operand meets every limb of the left one, so each row needs y_j only times 1, 2, 19 or 38, which takes the doubling of two odd limbs and the 19 of a column of 10 or more. 38·y_j for an odd j stays below 38·3.02·2^25 < 2^32.
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void Multiply(in Pair left, in Pair right, out Pair result)
		{
			Vector128<ulong> y = right.L0;
			Vector128<ulong> z0 = M(left.L0, y);
			Vector128<ulong> z1 = M(left.L1, y);
			Vector128<ulong> z2 = M(left.L2, y);
			Vector128<ulong> z3 = M(left.L3, y);
			Vector128<ulong> z4 = M(left.L4, y);
			Vector128<ulong> z5 = M(left.L5, y);
			Vector128<ulong> z6 = M(left.L6, y);
			Vector128<ulong> z7 = M(left.L7, y);
			Vector128<ulong> z8 = M(left.L8, y);
			Vector128<ulong> z9 = M(left.L9, y);

			y = right.L1;
			Vector128<ulong> twice = y + y;
			Vector128<ulong> wrapped = Times19(twice);
			z1 += M(left.L0, y);
			z2 += M(left.L1, twice);
			z3 += M(left.L2, y);
			z4 += M(left.L3, twice);
			z5 += M(left.L4, y);
			z6 += M(left.L5, twice);
			z7 += M(left.L6, y);
			z8 += M(left.L7, twice);
			z9 += M(left.L8, y);
			z0 += M(left.L9, wrapped);

			y = right.L2;
			wrapped = Times19(y);
			z2 += M(left.L0, y);
			z3 += M(left.L1, y);
			z4 += M(left.L2, y);
			z5 += M(left.L3, y);
			z6 += M(left.L4, y);
			z7 += M(left.L5, y);
			z8 += M(left.L6, y);
			z9 += M(left.L7, y);
			z0 += M(left.L8, wrapped);
			z1 += M(left.L9, wrapped);

			y = right.L3;
			twice = y + y;
			wrapped = Times19(y);
			Vector128<ulong> twiceWrapped = wrapped + wrapped;
			z3 += M(left.L0, y);
			z4 += M(left.L1, twice);
			z5 += M(left.L2, y);
			z6 += M(left.L3, twice);
			z7 += M(left.L4, y);
			z8 += M(left.L5, twice);
			z9 += M(left.L6, y);
			z0 += M(left.L7, twiceWrapped);
			z1 += M(left.L8, wrapped);
			z2 += M(left.L9, twiceWrapped);

			y = right.L4;
			wrapped = Times19(y);
			z4 += M(left.L0, y);
			z5 += M(left.L1, y);
			z6 += M(left.L2, y);
			z7 += M(left.L3, y);
			z8 += M(left.L4, y);
			z9 += M(left.L5, y);
			z0 += M(left.L6, wrapped);
			z1 += M(left.L7, wrapped);
			z2 += M(left.L8, wrapped);
			z3 += M(left.L9, wrapped);

			y = right.L5;
			twice = y + y;
			wrapped = Times19(y);
			twiceWrapped = wrapped + wrapped;
			z5 += M(left.L0, y);
			z6 += M(left.L1, twice);
			z7 += M(left.L2, y);
			z8 += M(left.L3, twice);
			z9 += M(left.L4, y);
			z0 += M(left.L5, twiceWrapped);
			z1 += M(left.L6, wrapped);
			z2 += M(left.L7, twiceWrapped);
			z3 += M(left.L8, wrapped);
			z4 += M(left.L9, twiceWrapped);

			y = right.L6;
			wrapped = Times19(y);
			z6 += M(left.L0, y);
			z7 += M(left.L1, y);
			z8 += M(left.L2, y);
			z9 += M(left.L3, y);
			z0 += M(left.L4, wrapped);
			z1 += M(left.L5, wrapped);
			z2 += M(left.L6, wrapped);
			z3 += M(left.L7, wrapped);
			z4 += M(left.L8, wrapped);
			z5 += M(left.L9, wrapped);

			y = right.L7;
			twice = y + y;
			wrapped = Times19(y);
			twiceWrapped = wrapped + wrapped;
			z7 += M(left.L0, y);
			z8 += M(left.L1, twice);
			z9 += M(left.L2, y);
			z0 += M(left.L3, twiceWrapped);
			z1 += M(left.L4, wrapped);
			z2 += M(left.L5, twiceWrapped);
			z3 += M(left.L6, wrapped);
			z4 += M(left.L7, twiceWrapped);
			z5 += M(left.L8, wrapped);
			z6 += M(left.L9, twiceWrapped);

			y = right.L8;
			wrapped = Times19(y);
			z8 += M(left.L0, y);
			z9 += M(left.L1, y);
			z0 += M(left.L2, wrapped);
			z1 += M(left.L3, wrapped);
			z2 += M(left.L4, wrapped);
			z3 += M(left.L5, wrapped);
			z4 += M(left.L6, wrapped);
			z5 += M(left.L7, wrapped);
			z6 += M(left.L8, wrapped);
			z7 += M(left.L9, wrapped);

			y = right.L9;
			wrapped = Times19(y);
			twiceWrapped = wrapped + wrapped;
			z9 += M(left.L0, y);
			z0 += M(left.L1, twiceWrapped);
			z1 += M(left.L2, wrapped);
			z2 += M(left.L3, twiceWrapped);
			z3 += M(left.L4, wrapped);
			z4 += M(left.L5, twiceWrapped);
			z5 += M(left.L6, wrapped);
			z6 += M(left.L7, twiceWrapped);
			z7 += M(left.L8, wrapped);
			z8 += M(left.L9, twiceWrapped);

			Reduce(z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, out result);
		}

		// The square row by row, limb j against limbs i ≤ j: a product with i < j counts twice, and the doubled factor goes on x_i where 38·x_j or 76·x_j would not fit 32 bits. For m ≤ 2.01 every multiplier stays below 2^31.3 and the columns are those of the square of Field25519x4Avx2. Where negateSecond is set, the second lane is subtracted from 2^37·p.
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void Square(in Pair value, bool negateSecond, out Pair result)
		{
			Vector128<ulong> x = value.L0;
			Vector128<ulong> z0 = M(x, x);

			x = value.L1;
			Vector128<ulong> twice = x + x;
			Vector128<ulong> z1 = M(value.L0, twice);
			Vector128<ulong> z2 = M(x, twice);

			x = value.L2;
			twice = x + x;
			z2 += M(value.L0, twice);
			Vector128<ulong> z3 = M(value.L1, twice);
			Vector128<ulong> z4 = M(x, x);

			x = value.L3;
			twice = x + x;
			Vector128<ulong> four = twice + twice;
			z3 += M(value.L0, twice);
			z4 += M(value.L1, four);
			Vector128<ulong> z5 = M(value.L2, twice);
			Vector128<ulong> z6 = M(x, twice);

			x = value.L4;
			twice = x + x;
			z4 += M(value.L0, twice);
			z5 += M(value.L1, twice);
			z6 += M(value.L2, twice);
			Vector128<ulong> z7 = M(value.L3, twice);
			Vector128<ulong> z8 = M(x, x);

			x = value.L5;
			twice = x + x;
			four = twice + twice;
			Vector128<ulong> wrapped = Times19(twice);
			z5 += M(value.L0, twice);
			z6 += M(value.L1, four);
			z7 += M(value.L2, twice);
			z8 += M(value.L3, four);
			Vector128<ulong> z9 = M(value.L4, twice);
			z0 += M(x, wrapped);

			x = value.L6;
			twice = x + x;
			wrapped = Times19(x);
			z6 += M(value.L0, twice);
			z7 += M(value.L1, twice);
			z8 += M(value.L2, twice);
			z9 += M(value.L3, twice);
			z0 += M(value.L4 + value.L4, wrapped);
			z1 += M(value.L5 + value.L5, wrapped);
			z2 += M(x, wrapped);

			x = value.L7;
			twice = x + x;
			four = twice + twice;
			wrapped = Times19(twice);
			z7 += M(value.L0, twice);
			z8 += M(value.L1, four);
			z9 += M(value.L2, twice);
			z0 += M(value.L3 + value.L3, wrapped);
			z1 += M(value.L4, wrapped);
			z2 += M(value.L5 + value.L5, wrapped);
			z3 += M(value.L6, wrapped);
			z4 += M(x, wrapped);

			x = value.L8;
			twice = x + x;
			wrapped = Times19(x);
			z8 += M(value.L0, twice);
			z9 += M(value.L1, twice);
			z0 += M(value.L2 + value.L2, wrapped);
			z1 += M(value.L3 + value.L3, wrapped);
			z2 += M(value.L4 + value.L4, wrapped);
			z3 += M(value.L5 + value.L5, wrapped);
			z4 += M(value.L6 + value.L6, wrapped);
			z5 += M(value.L7 + value.L7, wrapped);
			z6 += M(x, wrapped);

			x = value.L9;
			twice = x + x;
			wrapped = Times19(twice);
			z9 += M(value.L0, twice);
			z0 += M(value.L1 + value.L1, wrapped);
			z1 += M(value.L2, wrapped);
			z2 += M(value.L3 + value.L3, wrapped);
			z3 += M(value.L4, wrapped);
			z4 += M(value.L5 + value.L5, wrapped);
			z5 += M(value.L6, wrapped);
			z6 += M(value.L7 + value.L7, wrapped);
			z7 += M(value.L8, wrapped);
			z8 += M(x, wrapped);

			if (negateSecond)
			{
				z0 = NegateSecond(z0, P37Limb0);
				z1 = NegateSecond(z1, P37Odd);
				z2 = NegateSecond(z2, P37Even);
				z3 = NegateSecond(z3, P37Odd);
				z4 = NegateSecond(z4, P37Even);
				z5 = NegateSecond(z5, P37Odd);
				z6 = NegateSecond(z6, P37Even);
				z7 = NegateSecond(z7, P37Odd);
				z8 = NegateSecond(z8, P37Even);
				z9 = NegateSecond(z9, P37Odd);
			}

			Reduce(z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, out result);
		}

		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void MultiplySmall(in Pair value, Vector128<ulong> c, out Pair result)
		{
			Reduce(M(value.L0, c), M(value.L1, c), M(value.L2, c), M(value.L3, c), M(value.L4, c), M(value.L5, c), M(value.L6, c), M(value.L7, c), M(value.L8, c), M(value.L9, c), out result);
		}

		// Carries columns below 2^63, which leaves room for the carries a column takes before it is masked, to a reduced value in two chains, from limb 0 and from limb 4, that run side by side, with the carry out of limb 9, below 2^39, taken times 19 by shifts. Limb 1 takes the carry out of limb 0 last and ends below 2^25 + 2^17.3, limb 5 below 2^25 + 2^13 + 1 and the others below their nominal size, within the bounds that Field25519x4Avx2 gives a reduced value.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Reduce(Vector128<ulong> z0, Vector128<ulong> z1, Vector128<ulong> z2, Vector128<ulong> z3, Vector128<ulong> z4, Vector128<ulong> z5, Vector128<ulong> z6, Vector128<ulong> z7, Vector128<ulong> z8, Vector128<ulong> z9, out Pair result)
		{
			Vector128<ulong> mask25 = Vector128.Create(Mask25);
			Vector128<ulong> mask26 = Vector128.Create(Mask26);
			z1 += z0 >> 26;
			z0 &= mask26;
			z5 += z4 >> 26;
			z4 &= mask26;
			z2 += z1 >> 25;
			z1 &= mask25;
			z6 += z5 >> 25;
			z5 &= mask25;
			z3 += z2 >> 26;
			z2 &= mask26;
			z7 += z6 >> 26;
			z6 &= mask26;
			z4 += z3 >> 25;
			z3 &= mask25;
			z8 += z7 >> 25;
			z7 &= mask25;
			z5 += z4 >> 26;
			z4 &= mask26;
			z9 += z8 >> 26;
			z8 &= mask26;
			Vector128<ulong> carry = z9 >> 25;
			z0 += carry + (carry << 1) + (carry << 4);
			result.L1 = z1 + (z0 >> 26);
			result.L0 = z0 & mask26;
			result.L2 = z2;
			result.L3 = z3;
			result.L4 = z4;
			result.L5 = z5;
			result.L6 = z6;
			result.L7 = z7;
			result.L8 = z8;
			result.L9 = z9 & mask25;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Join(Vector128<ulong> l0, Vector128<ulong> l1, Vector128<ulong> l2, Vector128<ulong> l3, Vector128<ulong> l4, [ConstantExpected(Max = 1)] int lane, out Field25519 result)
		{
			Field25519 joined;
			joined.L0 = l0.GetElement(lane);
			joined.L1 = l1.GetElement(lane);
			joined.L2 = l2.GetElement(lane);
			joined.L3 = l3.GetElement(lane);
			joined.L4 = l4.GetElement(lane);
			Field25519.Carry(in joined, out result);
			joined.ZeroMemory();
		}

		// The low 32 bits of each 64-bit lane multiplied.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector128<ulong> M(Vector128<ulong> x, Vector128<ulong> y)
		{
			return Sse2.Multiply(x.AsUInt32(), y.AsUInt32());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector128<ulong> Times19(Vector128<ulong> y)
		{
			return Sse2.Multiply(y.AsUInt32(), Vector128.Create(19UL).AsUInt32());
		}
	}
}
