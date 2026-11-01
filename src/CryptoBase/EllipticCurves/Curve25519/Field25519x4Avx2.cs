using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.EllipticCurves.Curve25519;

// Four elements of the field of p = 2^255 − 19, one in each 64-bit lane A, B, C, D of the vectors, in ten limbs of radix 2^25.5: limb i weighs 2^⌈25.5i⌉, so the even limbs nominally hold 26 bits and the odd ones 25. The product of limbs i and j weighs 2^⌈25.5(i + j)⌉, times 2 when both are odd, and what weighs 2^255 or more comes back times 19.
// Bounds are per limb, as a multiple m of the nominal size: 2^26 for an even limb and 2^25 for an odd one. A value is reduced if m < 1.005, as every product leaves it: limb 0 below 2^26 + 2^17.3, limb 1 below 2^25 + 2^17.3 and every other below its nominal size plus 2^13 + 1. Every limb of a reduced value or of one with m ≤ 2 is at most that of 2p, so a difference adds 2p to stay positive and grows m by 2.
// Multiply takes a left operand with m_x ≤ 5.02 and a right one with m_y ≤ 3.02; the steps of the formulas give no more. Any result may be the same variable as an input: each member reads a limb of its inputs before it writes that limb of a result.
internal struct Field25519x4Avx2 : IField25519x4<Field25519x4Avx2>
{
	internal Vector256<ulong> L0;
	internal Vector256<ulong> L1;
	internal Vector256<ulong> L2;
	internal Vector256<ulong> L3;
	internal Vector256<ulong> L4;
	internal Vector256<ulong> L5;
	internal Vector256<ulong> L6;
	internal Vector256<ulong> L7;
	internal Vector256<ulong> L8;
	internal Vector256<ulong> L9;

	private const ulong Mask25 = (1UL << 25) - 1;
	private const ulong Mask26 = (1UL << 26) - 1;

	// (A − 2)/4 for the Montgomery coefficient A = 486662.
	private const ulong A24 = 121665;

	// The limbs of 2p.
	private const ulong TwoP0 = (1UL << 27) - 38;
	private const ulong TwoPEven = (1UL << 27) - 2;
	private const ulong TwoPOdd = (1UL << 26) - 2;

	// The limbs of 2^37·p, from which the square of a doubling subtracts its columns in lane D: each is above every column, which stays below 2^61.1 for its input, and below 2^63.
	private const ulong P37Limb0 = (1UL << 26) - 19 << 37;
	private const ulong P37Even = (1UL << 26) - 1 << 37;
	private const ulong P37Odd = (1UL << 25) - 1 << 37;

	// vpblendd masks of the 64-bit lanes.
	private const byte LaneA = 0x03;
	private const byte LaneB = 0x0C;
	private const byte LaneC = 0x30;
	private const byte LaneD = 0xC0;

	// vpermq controls, named by the lanes they take: Abdc takes (A, B, D, C).
	private const byte Aaaa = 0b00_00_00_00;
	private const byte Bbbb = 0b01_01_01_01;
	private const byte Cccc = 0b10_10_10_10;
	private const byte Dddd = 0b11_11_11_11;
	private const byte Abab = 0b01_00_01_00;
	private const byte Abdc = 0b10_11_01_00;
	private const byte Aacc = 0b10_10_00_00;
	private const byte Acca = 0b00_10_10_00;
	private const byte Bacd = 0b11_10_00_01;
	private const byte Caca = 0b00_10_00_10;
	private const byte Cdab = 0b01_00_11_10;
	private const byte Dbbd = 0b11_01_01_11;
	private const byte Dbdb = 0b01_11_01_11;

	// vpshufd control that swaps the 64-bit lanes of each 128-bit half: (B, A, D, C).
	private const byte Badc = 0b01_00_11_10;

	public static bool IsSupported => Avx2.IsSupported;

	// A tight limb of radix 2^51 splits into its low 26 bits and the rest, below 2^25 + 1.
	public static void Create(in Field25519 a, in Field25519 b, in Field25519 c, in Field25519 d, out Field25519x4Avx2 result)
	{
		Vector256<ulong> mask26 = Vector256.Create(Mask26);
		Vector256<ulong> l0 = Vector256.Create(a.L0, b.L0, c.L0, d.L0);
		Vector256<ulong> l1 = Vector256.Create(a.L1, b.L1, c.L1, d.L1);
		Vector256<ulong> l2 = Vector256.Create(a.L2, b.L2, c.L2, d.L2);
		Vector256<ulong> l3 = Vector256.Create(a.L3, b.L3, c.L3, d.L3);
		Vector256<ulong> l4 = Vector256.Create(a.L4, b.L4, c.L4, d.L4);
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

	// Each pair of limbs joins into a limb of radix 2^51 below 2^52, which Field25519.Carry leaves tight.
	public static void Extract(in Field25519x4Avx2 value, out Field25519 a, out Field25519 b, out Field25519 c, out Field25519 d)
	{
		Vector256<ulong> l0 = value.L0 + (value.L1 << 26);
		Vector256<ulong> l1 = value.L2 + (value.L3 << 26);
		Vector256<ulong> l2 = value.L4 + (value.L5 << 26);
		Vector256<ulong> l3 = value.L6 + (value.L7 << 26);
		Vector256<ulong> l4 = value.L8 + (value.L9 << 26);
		Join(l0, l1, l2, l3, l4, 0, out a);
		Join(l0, l1, l2, l3, l4, 1, out b);
		Join(l0, l1, l2, l3, l4, 2, out c);
		Join(l0, l1, l2, l3, l4, 3, out d);
	}

	// The column of weight 2^⌈25.5k⌉ takes x_i·y_j for i + j = k and 19·x_i·y_j for i + j = k + 10, doubled where i and j are odd: each term is below 2·m_x·m_y·2^51 for two even limbs and m_x·m_y·2^51 otherwise, so column 0, the largest, stays below 249·m_x·m_y·2^51 < 2^64. The columns gather row by row: limb j of the right operand meets every limb of the left one, which vpmuludq can read from memory, so the ten columns and the multiples of y_j fit sixteen registers. Each row needs y_j only times 1, 2, 19 or 38, for the doubling of two odd limbs and the 19 of a column of 10 or more; 38·y_j for an odd j and 19·y_j for an even one stay below 19·3.02·2^26 < 2^32, which the multiplier takes.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(in Field25519x4Avx2 left, in Field25519x4Avx2 right, out Field25519x4Avx2 result)
	{
		Product(in left, in right, false, out result);
	}

	// The first product of a step and the steps around it in one method, so that the values between them stay in registers. Its right operand, (A, B, A, B), is the first two lanes of its left one, (A, B, D, C), which each row takes in turn.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderOperands(in Field25519x4Avx2 state, ulong swap, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		PrepareLadder(in state, swap, out Field25519x4Avx2 sums);
		Product(in sums, in state, true, out Field25519x4Avx2 products);
		FinishLadder(in products, out Field25519x4Avx2 first, out Field25519x4Avx2 second);
		left = first;
		right = second;
	}

	// Three values, for the columns of lane D four at a time: lane l of limb i of value g holds the factor u_j·f_ij by which column k = 4g + l takes limb i of the other operand, with j = k − i mod 10, f_ij = 2 where i and j are odd, times 19 where i + j ≥ 10; the lanes past column 9 hold 0. The limbs of u, reduced, times 38 stay below 2^32.
	public static int MultiplierLength => 3;

	public static void CreateMultiplier(in Field25519 u, Span<Field25519x4Avx2> multiplier)
	{
		Debug.Assert(multiplier.Length is 3);

		Create(in u, in u, in u, in u, out Field25519x4Avx2 limbs);
		ReadOnlySpan<Vector256<ulong>> uLimbs = MemoryMarshal.CreateReadOnlySpan(ref limbs.L0, 10);
		Span<ulong> factors = MemoryMarshal.Cast<Field25519x4Avx2, ulong>(multiplier);

		for (int g = 0; g < 3; ++g)
		{
			for (int i = 0; i < 10; ++i)
			{
				for (int lane = 0; lane < 4; ++lane)
				{
					int k = 4 * g + lane;
					int j = (k - i + 10) % 10;
					ulong factor = (ulong)(1 + (i & j & 1)) * (k < i ? 19UL : 1);
					factors[(10 * g + i) * 4 + lane] = k < 10 ? uLimbs[j].ToScalar() * factor : 0;
				}
			}
		}
	}

	// The last two products of a step in one method: left·right, then that times (1, 1, 1, u). The second takes the columns of lane D, those of Multiply, four at a time from the multiplier of CreateMultiplier, with each limb of lane D in every lane, and puts each column into lane D of its limb; lanes A to C, reduced, go through the carries unchanged.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderProducts(in Field25519x4Avx2 left, in Field25519x4Avx2 right, in Field25519x4Avx2 multiplier, out Field25519x4Avx2 result)
	{
		Product(in left, in right, false, out Field25519x4Avx2 products);
		ref Field25519x4Avx2 low = ref Unsafe.AsRef(in multiplier);
		ref Field25519x4Avx2 middle = ref Unsafe.Add(ref low, 1);
		ref Field25519x4Avx2 high = ref Unsafe.Add(ref low, 2);
		Vector256<ulong> w = Avx2.Permute4x64(products.L0, Dddd);
		Vector256<ulong> c0 = M(w, low.L0);
		Vector256<ulong> c1 = M(w, middle.L0);
		Vector256<ulong> c2 = M(w, high.L0);
		w = Avx2.Permute4x64(products.L1, Dddd);
		c0 += M(w, low.L1);
		c1 += M(w, middle.L1);
		c2 += M(w, high.L1);
		w = Avx2.Permute4x64(products.L2, Dddd);
		c0 += M(w, low.L2);
		c1 += M(w, middle.L2);
		c2 += M(w, high.L2);
		w = Avx2.Permute4x64(products.L3, Dddd);
		c0 += M(w, low.L3);
		c1 += M(w, middle.L3);
		c2 += M(w, high.L3);
		w = Avx2.Permute4x64(products.L4, Dddd);
		c0 += M(w, low.L4);
		c1 += M(w, middle.L4);
		c2 += M(w, high.L4);
		w = Avx2.Permute4x64(products.L5, Dddd);
		c0 += M(w, low.L5);
		c1 += M(w, middle.L5);
		c2 += M(w, high.L5);
		w = Avx2.Permute4x64(products.L6, Dddd);
		c0 += M(w, low.L6);
		c1 += M(w, middle.L6);
		c2 += M(w, high.L6);
		w = Avx2.Permute4x64(products.L7, Dddd);
		c0 += M(w, low.L7);
		c1 += M(w, middle.L7);
		c2 += M(w, high.L7);
		w = Avx2.Permute4x64(products.L8, Dddd);
		c0 += M(w, low.L8);
		c1 += M(w, middle.L8);
		c2 += M(w, high.L8);
		w = Avx2.Permute4x64(products.L9, Dddd);
		c0 += M(w, low.L9);
		c1 += M(w, middle.L9);
		c2 += M(w, high.L9);
		Reduce(Blend(products.L0, Avx2.Permute4x64(c0, Aaaa), LaneD), Blend(products.L1, Avx2.Permute4x64(c0, Bbbb), LaneD), Blend(products.L2, Avx2.Permute4x64(c0, Cccc), LaneD), Blend(products.L3, c0, LaneD), Blend(products.L4, Avx2.Permute4x64(c1, Aaaa), LaneD), Blend(products.L5, Avx2.Permute4x64(c1, Bbbb), LaneD), Blend(products.L6, Avx2.Permute4x64(c1, Cccc), LaneD), Blend(products.L7, c1, LaneD), Blend(products.L8, Avx2.Permute4x64(c2, Aaaa), LaneD), Blend(products.L9, Avx2.Permute4x64(c2, Bbbb), LaneD), out result);
	}

	// The row operand y_j: limb j of right, or (A, B, A, B) of limb j of left where firstLanes is set.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Row(Vector256<ulong> left, Vector256<ulong> right, bool firstLanes)
	{
		return firstLanes ? Avx2.Permute4x64(left, Abab) : right;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Product(in Field25519x4Avx2 left, in Field25519x4Avx2 right, bool firstLanes, out Field25519x4Avx2 result)
	{
		Vector256<ulong> y = Row(left.L0, right.L0, firstLanes);
		Vector256<ulong> z0 = M(left.L0, y);
		Vector256<ulong> z1 = M(left.L1, y);
		Vector256<ulong> z2 = M(left.L2, y);
		Vector256<ulong> z3 = M(left.L3, y);
		Vector256<ulong> z4 = M(left.L4, y);
		Vector256<ulong> z5 = M(left.L5, y);
		Vector256<ulong> z6 = M(left.L6, y);
		Vector256<ulong> z7 = M(left.L7, y);
		Vector256<ulong> z8 = M(left.L8, y);
		Vector256<ulong> z9 = M(left.L9, y);

		y = Row(left.L1, right.L1, firstLanes);
		Vector256<ulong> twice = y + y;
		Vector256<ulong> wrapped = Times19(twice);
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

		y = Row(left.L2, right.L2, firstLanes);
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

		y = Row(left.L3, right.L3, firstLanes);
		twice = y + y;
		wrapped = Times19(y);
		Vector256<ulong> twiceWrapped = wrapped + wrapped;
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

		y = Row(left.L4, right.L4, firstLanes);
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

		y = Row(left.L5, right.L5, firstLanes);
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

		y = Row(left.L6, right.L6, firstLanes);
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

		y = Row(left.L7, right.L7, firstLanes);
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

		y = Row(left.L8, right.L8, firstLanes);
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

		y = Row(left.L9, right.L9, firstLanes);
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

	// The product of a readdition and the steps around it in one method, so that the values between them stay in registers.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void AddOperands(in Field25519x4Avx2 point, in Field25519x4Avx2 cached, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		DiffSum(in point, out Field25519x4Avx2 differences);
		Product(in differences, in cached, false, out Field25519x4Avx2 products);
		FinishAdd(in products, out Field25519x4Avx2 first, out Field25519x4Avx2 second);
		left = first;
		right = second;
	}

	// The squares of a doubling and the steps around them in one method.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void DoubleOperands(in Field25519x4Avx2 point, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		PrepareDouble(in point, out Field25519x4Avx2 prepared);
		Square(in prepared, out Field25519x4Avx2 squares);
		FinishDouble(in squares, out Field25519x4Avx2 first, out Field25519x4Avx2 second);
		left = first;
		right = second;
	}

	// As Multiply with right = value, row by row, limb j against limbs i ≤ j: a product with i < j counts twice, and the doubled factor goes on x_i where 38·x_j or 76·x_j would not fit 32 bits. For m ≤ 2.01 every multiplier stays below 2^31.3 and the columns below 249·2.01²·2^51 < 2^61.1. Lane D of each column is then subtracted from that of 2^37·p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Square(in Field25519x4Avx2 value, out Field25519x4Avx2 result)
	{
		Vector256<ulong> x = value.L0;
		Vector256<ulong> z0 = M(x, x);

		x = value.L1;
		Vector256<ulong> twice = x + x;
		Vector256<ulong> z1 = M(value.L0, twice);
		Vector256<ulong> z2 = M(x, twice);

		x = value.L2;
		twice = x + x;
		z2 += M(value.L0, twice);
		Vector256<ulong> z3 = M(value.L1, twice);
		Vector256<ulong> z4 = M(x, x);

		x = value.L3;
		twice = x + x;
		Vector256<ulong> four = twice + twice;
		z3 += M(value.L0, twice);
		z4 += M(value.L1, four);
		Vector256<ulong> z5 = M(value.L2, twice);
		Vector256<ulong> z6 = M(x, twice);

		x = value.L4;
		twice = x + x;
		z4 += M(value.L0, twice);
		z5 += M(value.L1, twice);
		z6 += M(value.L2, twice);
		Vector256<ulong> z7 = M(value.L3, twice);
		Vector256<ulong> z8 = M(x, x);

		x = value.L5;
		twice = x + x;
		four = twice + twice;
		Vector256<ulong> wrapped = Times19(twice);
		z5 += M(value.L0, twice);
		z6 += M(value.L1, four);
		z7 += M(value.L2, twice);
		z8 += M(value.L3, four);
		Vector256<ulong> z9 = M(value.L4, twice);
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

		Vector256<ulong> p0 = Vector256.Create(P37Limb0);
		Vector256<ulong> pEven = Vector256.Create(P37Even);
		Vector256<ulong> pOdd = Vector256.Create(P37Odd);
		Reduce(NegateD(z0, p0), NegateD(z1, pOdd), NegateD(z2, pEven), NegateD(z3, pOdd), NegateD(z4, pEven), NegateD(z5, pOdd), NegateD(z6, pEven), NegateD(z7, pOdd), NegateD(z8, pEven), NegateD(z9, pOdd), out result);
	}

	// Limbs below 2^32 times constants below 2^18 make columns below 2^50.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void MultiplySmall(in Field25519x4Avx2 value, uint a, uint b, uint c, uint d, out Field25519x4Avx2 result)
	{
		MultiplySmall(in value, Vector256.Create((ulong)a, b, c, d), out result);
	}

	// 2p − D, with m ≤ 2, for limbs at most those of 2p.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void NegateD(in Field25519x4Avx2 value, out Field25519x4Avx2 result)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		result.L0 = Blend(value.L0, twoP0 - value.L0, LaneD);
		result.L1 = Blend(value.L1, twoPOdd - value.L1, LaneD);
		result.L2 = Blend(value.L2, twoPEven - value.L2, LaneD);
		result.L3 = Blend(value.L3, twoPOdd - value.L3, LaneD);
		result.L4 = Blend(value.L4, twoPEven - value.L4, LaneD);
		result.L5 = Blend(value.L5, twoPOdd - value.L5, LaneD);
		result.L6 = Blend(value.L6, twoPEven - value.L6, LaneD);
		result.L7 = Blend(value.L7, twoPOdd - value.L7, LaneD);
		result.L8 = Blend(value.L8, twoPEven - value.L8, LaneD);
		result.L9 = Blend(value.L9, twoPOdd - value.L9, LaneD);
	}

	// Lane D of a cached point is reduced or 2p less a reduced lane, so 2p − D stays positive and its m at most 2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void NegateCached(in Field25519x4Avx2 value, out Field25519x4Avx2 result)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		result.L0 = NegateCached(value.L0, twoP0);
		result.L1 = NegateCached(value.L1, twoPOdd);
		result.L2 = NegateCached(value.L2, twoPEven);
		result.L3 = NegateCached(value.L3, twoPOdd);
		result.L4 = NegateCached(value.L4, twoPEven);
		result.L5 = NegateCached(value.L5, twoPOdd);
		result.L6 = NegateCached(value.L6, twoPEven);
		result.L7 = NegateCached(value.L7, twoPOdd);
		result.L8 = NegateCached(value.L8, twoPEven);
		result.L9 = NegateCached(value.L9, twoPOdd);
	}

	// Lane D, X + Y, has m ≤ 2.01.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareDouble(in Field25519x4Avx2 point, out Field25519x4Avx2 result)
	{
		result.L0 = PrepareDouble(point.L0);
		result.L1 = PrepareDouble(point.L1);
		result.L2 = PrepareDouble(point.L2);
		result.L3 = PrepareDouble(point.L3);
		result.L4 = PrepareDouble(point.L4);
		result.L5 = PrepareDouble(point.L5);
		result.L6 = PrepareDouble(point.L6);
		result.L7 = PrepareDouble(point.L7);
		result.L8 = PrepareDouble(point.L8);
		result.L9 = PrepareDouble(point.L9);
	}

	// From reduced squares, S5 has m ≤ 2.01, S6 and S9 m ≤ 3.02 and S8 = S1 + 2p − S2 + 2S3 m ≤ 5.02.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(in Field25519x4Avx2 squares, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		FinishDouble(squares.L0, twoP0, out left.L0, out right.L0);
		FinishDouble(squares.L1, twoPOdd, out left.L1, out right.L1);
		FinishDouble(squares.L2, twoPEven, out left.L2, out right.L2);
		FinishDouble(squares.L3, twoPOdd, out left.L3, out right.L3);
		FinishDouble(squares.L4, twoPEven, out left.L4, out right.L4);
		FinishDouble(squares.L5, twoPOdd, out left.L5, out right.L5);
		FinishDouble(squares.L6, twoPEven, out left.L6, out right.L6);
		FinishDouble(squares.L7, twoPOdd, out left.L7, out right.L7);
		FinishDouble(squares.L8, twoPEven, out left.L8, out right.L8);
		FinishDouble(squares.L9, twoPOdd, out left.L9, out right.L9);
	}

	// Y − X = Y + 2p − X has m ≤ 3.01 and Y + X m ≤ 2.01.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void DiffSum(in Field25519x4Avx2 point, out Field25519x4Avx2 result)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		result.L0 = DiffSum(point.L0, twoP0);
		result.L1 = DiffSum(point.L1, twoPOdd);
		result.L2 = DiffSum(point.L2, twoPEven);
		result.L3 = DiffSum(point.L3, twoPOdd);
		result.L4 = DiffSum(point.L4, twoPEven);
		result.L5 = DiffSum(point.L5, twoPOdd);
		result.L6 = DiffSum(point.L6, twoPEven);
		result.L7 = DiffSum(point.L7, twoPOdd);
		result.L8 = DiffSum(point.L8, twoPEven);
		result.L9 = DiffSum(point.L9, twoPOdd);
	}

	// From reduced products, the differences have m ≤ 3.01 and the sums m ≤ 2.01.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(in Field25519x4Avx2 products, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		FinishAdd(products.L0, twoP0, out left.L0, out right.L0);
		FinishAdd(products.L1, twoPOdd, out left.L1, out right.L1);
		FinishAdd(products.L2, twoPEven, out left.L2, out right.L2);
		FinishAdd(products.L3, twoPOdd, out left.L3, out right.L3);
		FinishAdd(products.L4, twoPEven, out left.L4, out right.L4);
		FinishAdd(products.L5, twoPOdd, out left.L5, out right.L5);
		FinishAdd(products.L6, twoPEven, out left.L6, out right.L6);
		FinishAdd(products.L7, twoPOdd, out left.L7, out right.L7);
		FinishAdd(products.L8, twoPEven, out left.L8, out right.L8);
		FinishAdd(products.L9, twoPOdd, out left.L9, out right.L9);
	}

	// The left operand (A, B, D, C) of the first product of a step; the right one, (A, B, A, B), is its first two lanes twice. The swap selects the lanes by the index of a vpermd, which takes the same time for every index. From a reduced state the sums have m ≤ 2.01 and the differences m ≤ 3.01.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(in Field25519x4Avx2 state, ulong swap, out Field25519x4Avx2 left)
	{
		Vector256<int> flip = Vector256.Create((int)swap & 4);
		Vector256<int> xs = Vector256.Create(0, 1, 0, 1, 4, 5, 4, 5) ^ flip;
		Vector256<int> zs = Vector256.Create(2, 3, 2, 3, 6, 7, 6, 7) ^ flip;
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		left.L0 = PrepareLadder(state.L0, xs, zs, twoP0);
		left.L1 = PrepareLadder(state.L1, xs, zs, twoPOdd);
		left.L2 = PrepareLadder(state.L2, xs, zs, twoPEven);
		left.L3 = PrepareLadder(state.L3, xs, zs, twoPOdd);
		left.L4 = PrepareLadder(state.L4, xs, zs, twoPEven);
		left.L5 = PrepareLadder(state.L5, xs, zs, twoPOdd);
		left.L6 = PrepareLadder(state.L6, xs, zs, twoPEven);
		left.L7 = PrepareLadder(state.L7, xs, zs, twoPOdd);
		left.L8 = PrepareLadder(state.L8, xs, zs, twoPEven);
		left.L9 = PrepareLadder(state.L9, xs, zs, twoPOdd);
	}

	// From (AA, BB, DA, CB), the operands (AA, E, DA + CB, DA − CB) and (BB, AA + a24·E, DA + CB, DA − CB) of the second product of a step: from reduced products, E and DA − CB have m ≤ 3.01 and DA + CB m ≤ 2.01. a24·E, with m ≤ 3.01 for E, has limbs below 2^44.5, which one carry from each limb into the next brings to m ≤ 1.11 in limb 0 and m ≤ 1.02 in the others; with AA the lane has m ≤ 2.12.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(in Field25519x4Avx2 products, out Field25519x4Avx2 left, out Field25519x4Avx2 right)
	{
		Vector256<ulong> twoP0 = Vector256.Create(TwoP0);
		Vector256<ulong> twoPEven = Vector256.Create(TwoPEven);
		Vector256<ulong> twoPOdd = Vector256.Create(TwoPOdd);
		FinishLadder(products.L0, twoP0, out left.L0, out right.L0, out Vector256<ulong> d0);
		FinishLadder(products.L1, twoPOdd, out left.L1, out right.L1, out Vector256<ulong> d1);
		FinishLadder(products.L2, twoPEven, out left.L2, out right.L2, out Vector256<ulong> d2);
		FinishLadder(products.L3, twoPOdd, out left.L3, out right.L3, out Vector256<ulong> d3);
		FinishLadder(products.L4, twoPEven, out left.L4, out right.L4, out Vector256<ulong> d4);
		FinishLadder(products.L5, twoPOdd, out left.L5, out right.L5, out Vector256<ulong> d5);
		FinishLadder(products.L6, twoPEven, out left.L6, out right.L6, out Vector256<ulong> d6);
		FinishLadder(products.L7, twoPOdd, out left.L7, out right.L7, out Vector256<ulong> d7);
		FinishLadder(products.L8, twoPEven, out left.L8, out right.L8, out Vector256<ulong> d8);
		FinishLadder(products.L9, twoPOdd, out left.L9, out right.L9, out Vector256<ulong> d9);
		Vector256<ulong> a24 = Vector256.Create(0, A24, 0, 0);
		Vector256<ulong> mask25 = Vector256.Create(Mask25);
		Vector256<ulong> mask26 = Vector256.Create(Mask26);
		d0 = M(d0, a24);
		d1 = M(d1, a24);
		d2 = M(d2, a24);
		d3 = M(d3, a24);
		d4 = M(d4, a24);
		d5 = M(d5, a24);
		d6 = M(d6, a24);
		d7 = M(d7, a24);
		d8 = M(d8, a24);
		d9 = M(d9, a24);
		right.L0 += (d0 & mask26) + Times19(d9 >> 25);
		right.L1 += (d1 & mask25) + (d0 >> 26);
		right.L2 += (d2 & mask26) + (d1 >> 25);
		right.L3 += (d3 & mask25) + (d2 >> 26);
		right.L4 += (d4 & mask26) + (d3 >> 25);
		right.L5 += (d5 & mask25) + (d4 >> 26);
		right.L6 += (d6 & mask26) + (d5 >> 25);
		right.L7 += (d7 & mask25) + (d6 >> 26);
		right.L8 += (d8 & mask26) + (d7 >> 25);
		right.L9 += (d9 & mask25) + (d8 >> 26);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field25519x4Avx2 value)
	{
		Vector256<ulong> select = Vector256.Create(mask);
		value.L0 = SwapHalves(value.L0, select);
		value.L1 = SwapHalves(value.L1, select);
		value.L2 = SwapHalves(value.L2, select);
		value.L3 = SwapHalves(value.L3, select);
		value.L4 = SwapHalves(value.L4, select);
		value.L5 = SwapHalves(value.L5, select);
		value.L6 = SwapHalves(value.L6, select);
		value.L7 = SwapHalves(value.L7, select);
		value.L8 = SwapHalves(value.L8, select);
		value.L9 = SwapHalves(value.L9, select);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void MultiplySmall(in Field25519x4Avx2 value, Vector256<ulong> constants, out Field25519x4Avx2 result)
	{
		Vector256<ulong> c = constants;
		Reduce(M(value.L0, c), M(value.L1, c), M(value.L2, c), M(value.L3, c), M(value.L4, c), M(value.L5, c), M(value.L6, c), M(value.L7, c), M(value.L8, c), M(value.L9, c), out result);
	}

	// Carries columns below 2^64 to a reduced value in two rounds, each limb at once, which take fewer steps one after another than a chain through the limbs. The first leaves limbs below 2^26 + 2^39, limb 0 below 2^26 + 2^43.3 once the carry out of limb 9, below 2^39, comes back times 19 by shifts; the second, whose carries are below 2^13 + 1 and 2^17.3 out of limb 0, leaves limb 0 below 2^26 + 2^17.3, limb 1 below 2^25 + 2^17.3 and the others below their nominal size plus 2^13 + 1, so m < 1.005.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce(Vector256<ulong> z0, Vector256<ulong> z1, Vector256<ulong> z2, Vector256<ulong> z3, Vector256<ulong> z4, Vector256<ulong> z5, Vector256<ulong> z6, Vector256<ulong> z7, Vector256<ulong> z8, Vector256<ulong> z9, out Field25519x4Avx2 result)
	{
		Vector256<ulong> mask25 = Vector256.Create(Mask25);
		Vector256<ulong> mask26 = Vector256.Create(Mask26);
		Vector256<ulong> carry = z9 >> 25;
		Vector256<ulong> r0 = (z0 & mask26) + carry + (carry << 1) + (carry << 4);
		Vector256<ulong> r1 = (z1 & mask25) + (z0 >> 26);
		Vector256<ulong> r2 = (z2 & mask26) + (z1 >> 25);
		Vector256<ulong> r3 = (z3 & mask25) + (z2 >> 26);
		Vector256<ulong> r4 = (z4 & mask26) + (z3 >> 25);
		Vector256<ulong> r5 = (z5 & mask25) + (z4 >> 26);
		Vector256<ulong> r6 = (z6 & mask26) + (z5 >> 25);
		Vector256<ulong> r7 = (z7 & mask25) + (z6 >> 26);
		Vector256<ulong> r8 = (z8 & mask26) + (z7 >> 25);
		Vector256<ulong> r9 = (z9 & mask25) + (z8 >> 26);
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
	private static void Join(Vector256<ulong> l0, Vector256<ulong> l1, Vector256<ulong> l2, Vector256<ulong> l3, Vector256<ulong> l4, int lane, out Field25519 result)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> NegateD(Vector256<ulong> column, Vector256<ulong> multiple)
	{
		return Blend(column, multiple - column, LaneD);
	}

	// (B, A, C, 2p − D).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> NegateCached(Vector256<ulong> limb, Vector256<ulong> twoP)
	{
		Vector256<ulong> swapped = Avx2.Permute4x64(limb, Bacd);
		return Blend(swapped, twoP - swapped, LaneD);
	}

	// (X, Y, Z, X + Y).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> PrepareDouble(Vector256<ulong> limb)
	{
		Vector256<ulong> xy = Avx2.Permute4x64(limb, Abab);
		return Blend(limb, xy + Swap(xy), LaneD);
	}

	// (S1, S2, S3, −S4) to (S5, S6, S8, S9) = (S1, S1, S1, S1) + (S2, −S2, −S2, S2) + (0, 0, 2S3, −S4), then the two operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishDouble(Vector256<ulong> limb, Vector256<ulong> twoP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> s2 = Avx2.Permute4x64(limb, Bbbb);
		Vector256<ulong> lanesCD = Blend(Vector256<ulong>.Zero, limb, LaneC | LaneD);
		Vector256<ulong> laneC = Blend(Vector256<ulong>.Zero, limb, LaneC);
		Vector256<ulong> sums = Avx2.Permute4x64(limb, Aaaa) + Blend(s2, twoP - s2, LaneB | LaneC) + lanesCD + laneC;
		left = Avx2.Permute4x64(sums, Caca);
		right = Avx2.Permute4x64(sums, Dbbd);
	}

	// (Y − X, Y + X, Z, T).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> DiffSum(Vector256<ulong> limb, Vector256<ulong> twoP)
	{
		Vector256<ulong> swapped = Swap(limb);
		return Blend(Blend(limb, swapped + twoP - limb, LaneA), swapped + limb, LaneB);
	}

	// (S8, S9, S10, S11) to (S12, S13, S15, S14), then the two operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishAdd(Vector256<ulong> limb, Vector256<ulong> twoP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> swapped = Swap(limb);
		Vector256<ulong> merged = Blend(swapped + twoP - limb, swapped + limb, LaneB | LaneC);
		left = Avx2.Permute4x64(merged, Acca);
		right = Avx2.Permute4x64(merged, Dbdb);
	}

	// (x2, x2, x3, x3) + (z2, −z2, z3, −z3) = (A, B, C, D), from the lanes that the swap selects.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> PrepareLadder(Vector256<ulong> limb, Vector256<int> xs, Vector256<int> zs, Vector256<ulong> twoP)
	{
		Vector256<ulong> x = Avx2.PermuteVar8x32(limb.AsInt32(), xs).AsUInt64();
		Vector256<ulong> z = Avx2.PermuteVar8x32(limb.AsInt32(), zs).AsUInt64();
		Vector256<ulong> sums = x + Blend(z, twoP - z, LaneB | LaneD);
		return Avx2.Permute4x64(sums, Abdc);
	}

	// From (AA, BB, DA, CB) and its swap (BB, AA, CB, DA): the differences (E, ·, DA − CB, ·) and sums (·, ·, DA + CB, ·).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector256<ulong> limb, Vector256<ulong> twoP, out Vector256<ulong> left, out Vector256<ulong> right, out Vector256<ulong> difference)
	{
		Vector256<ulong> swapped = Swap(limb);
		Vector256<ulong> sums = limb + swapped;
		Vector256<ulong> differences = Avx2.Permute4x64(limb + twoP - swapped, Aacc);
		left = Blend(Blend(limb, differences, LaneB | LaneD), sums, LaneC);
		right = Blend(Blend(swapped, sums, LaneC), differences, LaneD);
		difference = differences;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> SwapHalves(Vector256<ulong> limb, Vector256<ulong> mask)
	{
		return Vector256.ConditionalSelect(mask, Avx2.Permute4x64(limb, Cdab), limb);
	}

	// (B, A, D, C), within each 128-bit half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Swap(Vector256<ulong> limb)
	{
		return Avx2.Shuffle(limb.AsUInt32(), Badc).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend(Vector256<ulong> left, Vector256<ulong> right, [ConstantExpected] byte lanes)
	{
		// vpblendd has no EVEX form and takes only the first sixteen registers; with AVX-512 a vpternlogq takes any of the thirty-two.
		if (Avx512F.VL.IsSupported)
		{
			Vector256<ulong> mask = Vector256.Create(0 - (ulong)(lanes & 1), 0 - (ulong)(lanes >> 2 & 1), 0 - (ulong)(lanes >> 4 & 1), 0 - (ulong)(lanes >> 6 & 1));
			return Avx512F.VL.TernaryLogic(mask, right, left, 0xCA);
		}

		return Avx2.Blend(left.AsUInt32(), right.AsUInt32(), lanes).AsUInt64();
	}

	// The even 32-bit lanes multiplied into 64-bit lanes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> M(Vector256<ulong> x, Vector256<ulong> y)
	{
		return Avx2.Multiply(x.AsUInt32(), y.AsUInt32());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Times19(Vector256<ulong> y)
	{
		return Avx2.Multiply(y.AsUInt32(), Vector256.Create(19UL).AsUInt32());
	}
}
