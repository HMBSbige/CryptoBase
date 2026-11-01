namespace CryptoBase.EllipticCurves.Curve25519;

// Two groups of four field elements: each 256-bit half of the vectors holds a group in the layout of Field25519x4Avx2, the low half group 0 and the high half group 1, so one instruction carries the four-lane formulas of two independent points. The members take and give the bounds of Field25519x4Avx2.
// Any result may be the same variable as an input: each member reads a limb of its inputs before it writes that limb of a result.
internal struct Field25519x8Avx512 : IEdwardsField25519x4<Field25519x8Avx512>
{
	internal Vector512<ulong> L0;
	internal Vector512<ulong> L1;
	internal Vector512<ulong> L2;
	internal Vector512<ulong> L3;
	internal Vector512<ulong> L4;
	internal Vector512<ulong> L5;
	internal Vector512<ulong> L6;
	internal Vector512<ulong> L7;
	internal Vector512<ulong> L8;
	internal Vector512<ulong> L9;

	private const ulong Mask25 = (1UL << 25) - 1;
	private const ulong Mask26 = (1UL << 26) - 1;

	private const ulong TwoP0 = (1UL << 27) - 38;
	private const ulong TwoPEven = (1UL << 27) - 2;
	private const ulong TwoPOdd = (1UL << 26) - 2;

	private const ulong P37Limb0 = (1UL << 26) - 19 << 37;
	private const ulong P37Even = (1UL << 26) - 1 << 37;
	private const ulong P37Odd = (1UL << 25) - 1 << 37;

	// The lanes of each half, as bits of a blend mask.
	private const byte LaneA = 0b0001;
	private const byte LaneB = 0b0010;
	private const byte LaneC = 0b0100;
	private const byte LaneD = 0b1000;

	// vpermq controls within each half, named as in Field25519x4Avx2.
	private const byte Aaaa = 0b00_00_00_00;
	private const byte Bbbb = 0b01_01_01_01;
	private const byte Abab = 0b01_00_01_00;
	private const byte Acca = 0b00_10_10_00;
	private const byte Caca = 0b00_10_00_10;
	private const byte Dbbd = 0b11_01_01_11;
	private const byte Dbdb = 0b01_11_01_11;

	// vpshufd control that swaps the 64-bit lanes of each 128-bit quarter.
	private const byte Badc = 0b01_00_11_10;

	// The vpternlogq table of A ? B : C.
	private const byte Select = 0xCA;

	public static bool IsSupported => Avx512F.IsSupported && Vector512.IsHardwareAccelerated;

	// Group 0 from (a0, b0, c0, d0) and group 1 from (a1, b1, c1, d1), for tight elements.
	public static void Create(in Field25519 a0, in Field25519 b0, in Field25519 c0, in Field25519 d0, in Field25519 a1, in Field25519 b1, in Field25519 c1, in Field25519 d1, out Field25519x8Avx512 result)
	{
		Vector512<ulong> mask26 = Vector512.Create(Mask26);
		Vector512<ulong> l0 = Vector512.Create(a0.L0, b0.L0, c0.L0, d0.L0, a1.L0, b1.L0, c1.L0, d1.L0);
		Vector512<ulong> l1 = Vector512.Create(a0.L1, b0.L1, c0.L1, d0.L1, a1.L1, b1.L1, c1.L1, d1.L1);
		Vector512<ulong> l2 = Vector512.Create(a0.L2, b0.L2, c0.L2, d0.L2, a1.L2, b1.L2, c1.L2, d1.L2);
		Vector512<ulong> l3 = Vector512.Create(a0.L3, b0.L3, c0.L3, d0.L3, a1.L3, b1.L3, c1.L3, d1.L3);
		Vector512<ulong> l4 = Vector512.Create(a0.L4, b0.L4, c0.L4, d0.L4, a1.L4, b1.L4, c1.L4, d1.L4);
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

	// The four lanes of group 0 or 1 as tight elements.
	public static void Extract(in Field25519x8Avx512 value, int group, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d)
	{
		Vector512<ulong> l0 = value.L0 + (value.L1 << 26);
		Vector512<ulong> l1 = value.L2 + (value.L3 << 26);
		Vector512<ulong> l2 = value.L4 + (value.L5 << 26);
		Vector512<ulong> l3 = value.L6 + (value.L7 << 26);
		Vector512<ulong> l4 = value.L8 + (value.L9 << 26);
		int first = 4 * group;
		Join(l0, l1, l2, l3, l4, first, out a);
		Join(l0, l1, l2, l3, l4, first + 1, out b);
		Join(l0, l1, l2, l3, l4, first + 2, out c);
		Join(l0, l1, l2, l3, l4, first + 3, out d);
	}

	// The columns and bounds of Field25519x4Avx2.Multiply.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(in Field25519x8Avx512 left, in Field25519x8Avx512 right, out Field25519x8Avx512 result)
	{
		Product(in left, in right, out result);
	}

	// The product of a readdition and the steps around it in one method, so that the values between them stay in registers.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void AddOperands(in Field25519x8Avx512 point, in Field25519x8Avx512 cached, out Field25519x8Avx512 left, out Field25519x8Avx512 right)
	{
		DiffSum(in point, out Field25519x8Avx512 differences);
		Product(in differences, in cached, out Field25519x8Avx512 products);
		FinishAdd(in products, out Field25519x8Avx512 first, out Field25519x8Avx512 second);
		left = first;
		right = second;
	}

	// The squares of a doubling and the steps around them in one method.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void DoubleOperands(in Field25519x8Avx512 point, out Field25519x8Avx512 left, out Field25519x8Avx512 right)
	{
		PrepareDouble(in point, out Field25519x8Avx512 prepared);
		Square(in prepared, out Field25519x8Avx512 squares);
		FinishDouble(in squares, out Field25519x8Avx512 first, out Field25519x8Avx512 second);
		left = first;
		right = second;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Product(in Field25519x8Avx512 left, in Field25519x8Avx512 right, out Field25519x8Avx512 result)
	{
		Vector512<ulong> y = right.L0;
		Vector512<ulong> z0 = M(left.L0, y);
		Vector512<ulong> z1 = M(left.L1, y);
		Vector512<ulong> z2 = M(left.L2, y);
		Vector512<ulong> z3 = M(left.L3, y);
		Vector512<ulong> z4 = M(left.L4, y);
		Vector512<ulong> z5 = M(left.L5, y);
		Vector512<ulong> z6 = M(left.L6, y);
		Vector512<ulong> z7 = M(left.L7, y);
		Vector512<ulong> z8 = M(left.L8, y);
		Vector512<ulong> z9 = M(left.L9, y);

		y = right.L1;
		Vector512<ulong> twice = y + y;
		Vector512<ulong> wrapped = Times19(twice);
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
		Vector512<ulong> twiceWrapped = wrapped + wrapped;
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

	// The columns and bounds of the square of Field25519x4Avx2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Square(in Field25519x8Avx512 value, out Field25519x8Avx512 result)
	{
		Vector512<ulong> x = value.L0;
		Vector512<ulong> z0 = M(x, x);

		x = value.L1;
		Vector512<ulong> twice = x + x;
		Vector512<ulong> z1 = M(value.L0, twice);
		Vector512<ulong> z2 = M(x, twice);

		x = value.L2;
		twice = x + x;
		z2 += M(value.L0, twice);
		Vector512<ulong> z3 = M(value.L1, twice);
		Vector512<ulong> z4 = M(x, x);

		x = value.L3;
		twice = x + x;
		Vector512<ulong> four = twice + twice;
		z3 += M(value.L0, twice);
		z4 += M(value.L1, four);
		Vector512<ulong> z5 = M(value.L2, twice);
		Vector512<ulong> z6 = M(x, twice);

		x = value.L4;
		twice = x + x;
		z4 += M(value.L0, twice);
		z5 += M(value.L1, twice);
		z6 += M(value.L2, twice);
		Vector512<ulong> z7 = M(value.L3, twice);
		Vector512<ulong> z8 = M(x, x);

		x = value.L5;
		twice = x + x;
		four = twice + twice;
		Vector512<ulong> wrapped = Times19(twice);
		z5 += M(value.L0, twice);
		z6 += M(value.L1, four);
		z7 += M(value.L2, twice);
		z8 += M(value.L3, four);
		Vector512<ulong> z9 = M(value.L4, twice);
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

		Vector512<ulong> laneD = LaneMask(LaneD);
		Reduce(NegateD(z0, P37Limb0, laneD), NegateD(z1, P37Odd, laneD), NegateD(z2, P37Even, laneD), NegateD(z3, P37Odd, laneD), NegateD(z4, P37Even, laneD), NegateD(z5, P37Odd, laneD), NegateD(z6, P37Even, laneD), NegateD(z7, P37Odd, laneD), NegateD(z8, P37Even, laneD), NegateD(z9, P37Odd, laneD), out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(in Field25519x8Avx512 point, out Field25519x8Avx512 result)
	{
		Vector512<ulong> laneD = LaneMask(LaneD);
		result.L0 = PrepareDouble(point.L0, laneD);
		result.L1 = PrepareDouble(point.L1, laneD);
		result.L2 = PrepareDouble(point.L2, laneD);
		result.L3 = PrepareDouble(point.L3, laneD);
		result.L4 = PrepareDouble(point.L4, laneD);
		result.L5 = PrepareDouble(point.L5, laneD);
		result.L6 = PrepareDouble(point.L6, laneD);
		result.L7 = PrepareDouble(point.L7, laneD);
		result.L8 = PrepareDouble(point.L8, laneD);
		result.L9 = PrepareDouble(point.L9, laneD);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(in Field25519x8Avx512 squares, out Field25519x8Avx512 left, out Field25519x8Avx512 right)
	{
		FinishDouble(squares.L0, TwoP0, out left.L0, out right.L0);
		FinishDouble(squares.L1, TwoPOdd, out left.L1, out right.L1);
		FinishDouble(squares.L2, TwoPEven, out left.L2, out right.L2);
		FinishDouble(squares.L3, TwoPOdd, out left.L3, out right.L3);
		FinishDouble(squares.L4, TwoPEven, out left.L4, out right.L4);
		FinishDouble(squares.L5, TwoPOdd, out left.L5, out right.L5);
		FinishDouble(squares.L6, TwoPEven, out left.L6, out right.L6);
		FinishDouble(squares.L7, TwoPOdd, out left.L7, out right.L7);
		FinishDouble(squares.L8, TwoPEven, out left.L8, out right.L8);
		FinishDouble(squares.L9, TwoPOdd, out left.L9, out right.L9);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DiffSum(in Field25519x8Avx512 point, out Field25519x8Avx512 result)
	{
		result.L0 = DiffSum(point.L0, TwoP0);
		result.L1 = DiffSum(point.L1, TwoPOdd);
		result.L2 = DiffSum(point.L2, TwoPEven);
		result.L3 = DiffSum(point.L3, TwoPOdd);
		result.L4 = DiffSum(point.L4, TwoPEven);
		result.L5 = DiffSum(point.L5, TwoPOdd);
		result.L6 = DiffSum(point.L6, TwoPEven);
		result.L7 = DiffSum(point.L7, TwoPOdd);
		result.L8 = DiffSum(point.L8, TwoPEven);
		result.L9 = DiffSum(point.L9, TwoPOdd);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(in Field25519x8Avx512 products, out Field25519x8Avx512 left, out Field25519x8Avx512 right)
	{
		FinishAdd(products.L0, TwoP0, out left.L0, out right.L0);
		FinishAdd(products.L1, TwoPOdd, out left.L1, out right.L1);
		FinishAdd(products.L2, TwoPEven, out left.L2, out right.L2);
		FinishAdd(products.L3, TwoPOdd, out left.L3, out right.L3);
		FinishAdd(products.L4, TwoPEven, out left.L4, out right.L4);
		FinishAdd(products.L5, TwoPOdd, out left.L5, out right.L5);
		FinishAdd(products.L6, TwoPEven, out left.L6, out right.L6);
		FinishAdd(products.L7, TwoPOdd, out left.L7, out right.L7);
		FinishAdd(products.L8, TwoPEven, out left.L8, out right.L8);
		FinishAdd(products.L9, TwoPOdd, out left.L9, out right.L9);
	}

	// The two rounds of carries of Field25519x4Avx2's Reduce, with its bounds.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(Vector512<ulong> z0, Vector512<ulong> z1, Vector512<ulong> z2, Vector512<ulong> z3, Vector512<ulong> z4, Vector512<ulong> z5, Vector512<ulong> z6, Vector512<ulong> z7, Vector512<ulong> z8, Vector512<ulong> z9, out Field25519x8Avx512 result)
	{
		Vector512<ulong> mask25 = Vector512.Create(Mask25);
		Vector512<ulong> mask26 = Vector512.Create(Mask26);
		Vector512<ulong> carry = z9 >> 25;
		Vector512<ulong> r0 = (z0 & mask26) + carry + (carry << 1) + (carry << 4);
		Vector512<ulong> r1 = (z1 & mask25) + (z0 >> 26);
		Vector512<ulong> r2 = (z2 & mask26) + (z1 >> 25);
		Vector512<ulong> r3 = (z3 & mask25) + (z2 >> 26);
		Vector512<ulong> r4 = (z4 & mask26) + (z3 >> 25);
		Vector512<ulong> r5 = (z5 & mask25) + (z4 >> 26);
		Vector512<ulong> r6 = (z6 & mask26) + (z5 >> 25);
		Vector512<ulong> r7 = (z7 & mask25) + (z6 >> 26);
		Vector512<ulong> r8 = (z8 & mask26) + (z7 >> 25);
		Vector512<ulong> r9 = (z9 & mask25) + (z8 >> 26);
		result.L0 = (r0 & mask26) + Times19(r9 >> 25);
		result.L1 = (r1 & mask25) + (r0 >> 26);
		result.L2 = (r2 & mask26) + (r1 >> 25);
		result.L3 = (r3 & mask25) + (r2 >> 26);
		result.L4 = (r4 & mask26) + (r3 >> 25);
		result.L5 = (r5 & mask25) + (r4 >> 26);
		result.L6 = (r6 & mask26) + (r5 >> 25);
		result.L7 = (r7 & mask25) + (r6 >> 26);
		result.L8 = (r8 & mask26) + (r7 >> 25);
		result.L9 = (r9 & mask25) + (r8 >> 26);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Join(Vector512<ulong> l0, Vector512<ulong> l1, Vector512<ulong> l2, Vector512<ulong> l3, Vector512<ulong> l4, int lane, out Field25519 result)
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

	// All ones in the lanes of each half that lanes sets. The eight scalars fold to a constant, where a vector of two halves may cost calls once the inlining budget runs out.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> LaneMask(byte lanes)
	{
		ulong a = (lanes & LaneA) is 0 ? 0 : ulong.MaxValue;
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
	private static Vector512<ulong> NegateD(Vector512<ulong> column, ulong multiple, Vector512<ulong> laneD)
	{
		return Blend(column, Vector512.Create(multiple) - column, laneD);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> PrepareDouble(Vector512<ulong> limbs, Vector512<ulong> laneD)
	{
		Vector512<ulong> xy = Avx512F.Permute4x64(limbs, Abab);
		return Blend(limbs, xy + Swap(xy), laneD);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector512<ulong> limbs, ulong twoP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> s2 = Avx512F.Permute4x64(limbs, Bbbb);
		Vector512<ulong> sums = Avx512F.Permute4x64(limbs, Aaaa) + Blend(s2, Vector512.Create(twoP) - s2, LaneMask(LaneB | LaneC)) + (limbs & LaneMask(LaneC | LaneD)) + (limbs & LaneMask(LaneC));
		left = Avx512F.Permute4x64(sums, Caca);
		right = Avx512F.Permute4x64(sums, Dbbd);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> DiffSum(Vector512<ulong> limbs, ulong twoP)
	{
		Vector512<ulong> swapped = Swap(limbs);
		return Blend(Blend(limbs, swapped + Vector512.Create(twoP) - limbs, LaneMask(LaneA)), swapped + limbs, LaneMask(LaneB));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector512<ulong> limbs, ulong twoP, out Vector512<ulong> left, out Vector512<ulong> right)
	{
		Vector512<ulong> swapped = Swap(limbs);
		Vector512<ulong> merged = Blend(swapped + Vector512.Create(twoP) - limbs, swapped + limbs, LaneMask(LaneB | LaneC));
		left = Avx512F.Permute4x64(merged, Acca);
		right = Avx512F.Permute4x64(merged, Dbdb);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Swap(Vector512<ulong> limbs)
	{
		return Avx512F.Shuffle(limbs.AsUInt32(), Badc).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> M(Vector512<ulong> x, Vector512<ulong> y)
	{
		return Avx512F.Multiply(x.AsUInt32(), y.AsUInt32());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Times19(Vector512<ulong> y)
	{
		return Avx512F.Multiply(y.AsUInt32(), Vector512.Create(19UL).AsUInt32());
	}
}
