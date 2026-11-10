using System.Diagnostics.CodeAnalysis;
using static CryptoBase.EllipticCurves.Curve448.Field448Blocks<System.Runtime.Intrinsics.Vector256<ulong>, CryptoBase.EllipticCurves.Curve448.Field448Vector256>;

namespace CryptoBase.EllipticCurves.Curve448;

// Four elements of the field of p = 2^448 − 2^224 − 1, one in each 64-bit lane A, B, C, D of the vectors, in sixteen limbs of radix 2^28: limb i weighs 2^(28i). With φ = 2^224, limbs 0 to 7 hold x_lo and limbs 8 to 15 x_hi of x = x_lo + φ·x_hi, and p = φ² − φ − 1, so φ² ≡ φ + 1.
// Bounds are per limb, as a multiple m of 2^28. Every member that gives a value leaves it reduced, every limb below 2^28 + 2^9, so m < 1 + 2^−19; a product leaves limbs below 2^28 except limb 1, below 2^28 + 2^8, and limb 9.
// Product takes operands with m_x·m_y ≤ 6.7, m_x < 8 and m_y < 5.3.
internal partial struct Field448x4Avx2 : IField448Lanes<Field448x4Avx2>
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
	internal Vector256<ulong> L10;
	internal Vector256<ulong> L11;
	internal Vector256<ulong> L12;
	internal Vector256<ulong> L13;
	internal Vector256<ulong> L14;
	internal Vector256<ulong> L15;

	// The limbs of 8p, each at least the largest limb of four times a reduced value; limb 8 is the smaller.
	private const ulong EightP = (1UL << 31) - 8;
	private const ulong EightP8 = (1UL << 31) - 16;

	// 16·a24 for a24 = (A − 2)/4 = 39081.
	private const ulong SixteenA24 = 16 * 39081;

	// A step keeps its products at Products, after the operands of Product.
	private const int Products = 56;

	// vpblendd masks of the 64-bit lanes.
	private const byte LaneB = 0x0C;
	private const byte LaneC = 0x30;
	private const byte LaneD = 0xC0;

	// vpermq controls, named by the lanes they take.
	private const byte Aaaa = 0b00_00_00_00;
	private const byte Bbbb = 0b01_01_01_01;
	private const byte Cccc = 0b10_10_10_10;
	private const byte Abdc = 0b10_11_01_00;
	private const byte Aaab = 0b01_00_00_00;
	private const byte Cdab = 0b01_00_11_10;

	// vpshufd control that swaps the 64-bit lanes of each 128-bit half: (B, A, D, C).
	private const byte Badc = 0b01_00_11_10;

	public static bool IsSupported => Avx2.IsSupported;

	// The 56-bit limb i of each element splits into limbs 2i, its low 28 bits, and 2i + 1, the rest, below 2^29; one carry from each odd limb into the next, with the one out of limb 15 back into limbs 0 and 8, leaves every limb below 2^28 + 2.
	public static void Create(in Field448 a, in Field448 b, in Field448 c, in Field448 d, out Field448x4Avx2 result)
	{
		Vector256<ulong> mask = Vector256.Create(Mask);
		Vector256<ulong> w0 = Vector256.Create(a.L0, b.L0, c.L0, d.L0);
		Vector256<ulong> w1 = Vector256.Create(a.L1, b.L1, c.L1, d.L1);
		Vector256<ulong> w2 = Vector256.Create(a.L2, b.L2, c.L2, d.L2);
		Vector256<ulong> w3 = Vector256.Create(a.L3, b.L3, c.L3, d.L3);
		Vector256<ulong> w4 = Vector256.Create(a.L4, b.L4, c.L4, d.L4);
		Vector256<ulong> w5 = Vector256.Create(a.L5, b.L5, c.L5, d.L5);
		Vector256<ulong> w6 = Vector256.Create(a.L6, b.L6, c.L6, d.L6);
		Vector256<ulong> w7 = Vector256.Create(a.L7, b.L7, c.L7, d.L7);
		Vector256<ulong> top = w7 >> 2 * Bits;
		result.L0 = (w0 & mask) + top;
		result.L1 = w0 >> Bits & mask;
		result.L2 = (w1 & mask) + (w0 >> 2 * Bits);
		result.L3 = w1 >> Bits & mask;
		result.L4 = (w2 & mask) + (w1 >> 2 * Bits);
		result.L5 = w2 >> Bits & mask;
		result.L6 = (w3 & mask) + (w2 >> 2 * Bits);
		result.L7 = w3 >> Bits & mask;
		result.L8 = (w4 & mask) + (w3 >> 2 * Bits) + top;
		result.L9 = w4 >> Bits & mask;
		result.L10 = (w5 & mask) + (w4 >> 2 * Bits);
		result.L11 = w5 >> Bits & mask;
		result.L12 = (w6 & mask) + (w5 >> 2 * Bits);
		result.L13 = w6 >> Bits & mask;
		result.L14 = (w7 & mask) + (w6 >> 2 * Bits);
		result.L15 = w7 >> Bits & mask;
	}

	public static void Extract(in Field448x4Avx2 value, out Field448 a, out Field448 b, out Field448 c, out Field448 d)
	{
		Field448.FromRadix28(in value, 0, out a);
		Field448.FromRadix28(in value, 1, out b);
		Field448.FromRadix28(in value, 2, out c);
		Field448.FromRadix28(in value, 3, out d);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong Limb(in Field448x4Avx2 value, int limb, int lane)
	{
		return Unsafe.Add(ref Unsafe.AsRef(in value.L0), limb).GetElement(lane);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field448x4Avx2 value)
	{
		Vector256<ulong> select = Vector256.Create(mask);
		ref Vector256<ulong> limbs = ref value.L0;

		for (nint i = 0; i < 16; ++i)
		{
			ref Vector256<ulong> limb = ref Unsafe.Add(ref limbs, i);
			limb = Vector256.ConditionalSelect(select, Avx2.Permute4x64(limb, Cdab), limb);
		}
	}

	// Four values, for the columns of lane D four at a time: lane l of limb i of value g holds the factor f_ik by which column k = 4g + l takes limb i of the other operand. Each column sums 38 products of limbs at most.
	public static int MultiplierLength => 4;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong LaneALimb(in Field448x4Avx2 value, int limb)
	{
		return Unsafe.Add(ref Unsafe.AsRef(in value.L0), limb).ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddFactor(Span<ulong> factors, int limb, int column, ulong term)
	{
		factors[(column >> 2) * 64 + limb * 4 + (column & 3)] += term;
	}

	// The operands and the products of a step in five values, and the doubled operand of a square in a sixth.
	public static int ScratchLength => 6;

	// The two products of four lanes and the product of lane D by u, each over operands that the step before writes into scratch. With w = x2·z2, E = 4w, so the first product is (A², w, DA, CB), whose operands need no carry: their lanes multiply to m ≤ 6, as A and C have m ≤ 2 and B and D m ≤ 3. The second, (AA·BB, E·(AA + a24·E), (DA + CB)², (DA − CB)²), takes BB as AA − 4w and E·(AA + a24·E) as w·(4AA + 16a24·w).
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderStep(ref Field448x4Avx2 state, ulong swap, in Field448x4Avx2 multiplier, ref Field448x4Avx2 scratch)
	{
		ref Vector256<ulong> operands = ref scratch.L0;
		ref Vector256<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareLadder(ref state.L0, swap, ref operands);
		Product(ref operands, ref products);
		FinishLadder(ref products, ref operands);
		Product(ref operands, ref products);
		MultiplyLaneD(ref products, ref Unsafe.AsRef(in multiplier.L0), ref state.L0);
	}

	// The left operand (A, x2, D, C) of the first product and the right one, (A, z2, A, B), from the lanes that the swap selects by the index of a vpermd, which takes the same time for every index. Limbs i and i + 8 go together, as Product takes the sums of the halves.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(ref Vector256<ulong> state, ulong swap, ref Vector256<ulong> operands)
	{
		Vector256<int> flip = Vector256.Create((int)swap & 4);
		Vector256<int> xs = Vector256.Create(0, 1, 0, 1, 4, 5, 4, 5) ^ flip;
		Vector256<int> zs = Vector256.Create(2, 3, 2, 3, 6, 7, 6, 7) ^ flip;
		Vector256<ulong> twoP = Vector256.Create(TwoP);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareLadder(Unsafe.Add(ref state, i), xs, zs, twoP, out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			PrepareLadder(Unsafe.Add(ref state, i + 8), xs, zs, Vector256.Create(i is 0 ? TwoP8 : TwoP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			Unsafe.Add(ref operands, Sums + i) = leftLow + leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}
	}

	// (x2, x2, x3, x3) + (z2, 2p − z2, z3, 2p − z3) = (A, B, C, D), then the operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(Vector256<ulong> limb, Vector256<int> xs, Vector256<int> zs, Vector256<ulong> twoP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> x = Avx2.PermuteVar8x32(limb.AsInt32(), xs).AsUInt64();
		Vector256<ulong> z = Avx2.PermuteVar8x32(limb.AsInt32(), zs).AsUInt64();
		Vector256<ulong> sums = x + Blend(z, twoP - z, LaneB | LaneD);
		left = Blend(Avx2.Permute4x64(sums, Abdc), x, LaneB);
		right = Blend(Avx2.Permute4x64(sums, Aaab), z, LaneB);
	}

	// From (AA, w, DA, CB): the left operand of the second product, (AA + 8p − 4w, 4AA + 16a24·w, DA + CB, DA + 2p − CB), carried once from each limb into the next, and the right one, (AA, w, DA + CB, DA + 2p − CB). Before the carry the lanes of the left one are below 2^31.2, 2^47.3, 2^29.1 and 2^29.6, so the carries are below 2^19.3, limb 8 takes two, and the left operand has m < 1.005; the right one has m < 3 + 2^−18, so the lanes multiply to m_x·m_y < 3.02.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(ref Vector256<ulong> products, ref Vector256<ulong> operands)
	{
		Vector256<ulong> twoP = Vector256.Create(TwoP);
		Vector256<ulong> eightP = Vector256.Create(EightP);

		for (nint i = 0; i < 8; ++i)
		{
			FinishLadder(Unsafe.Add(ref products, i), twoP, eightP, out Vector256<ulong> leftLow, out Vector256<ulong> rightLow);
			FinishLadder(Unsafe.Add(ref products, i + 8), Vector256.Create(i is 0 ? TwoP8 : TwoP), Vector256.Create(i is 0 ? EightP8 : EightP), out Vector256<ulong> leftHigh, out Vector256<ulong> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}

		CarryLeft(ref operands);
	}

	// (AA, w, DA, CB) and its swap (w, AA, CB, DA) to the lanes of the operands.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector256<ulong> limb, Vector256<ulong> twoP, Vector256<ulong> eightP, out Vector256<ulong> left, out Vector256<ulong> right)
	{
		Vector256<ulong> swapped = Swap(limb);
		Vector256<ulong> sums = limb + swapped;
		Vector256<ulong> differences = swapped + twoP - limb;
		Vector256<ulong> four = swapped << 2;
		Vector256<ulong> first = limb + eightP - four;
		Vector256<ulong> second = four + M(limb, Vector256.Create(0, SixteenA24, 0, 0));
		Vector256<ulong> tail = Blend(sums, differences, LaneD);
		left = Blend(Blend(first, second, LaneB), tail, LaneC | LaneD);
		right = Blend(limb, tail, LaneC | LaneD);
	}

	// The columns of lane D of the products times u, four at a time from the multiplier, each limb of lane D in every lane by Lane; column k, below 38·(2^28 + 2^9)², goes into lane D of limb k, and the limbs of all four lanes then carry as a product's columns do, which keeps their values.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyLaneD(ref Vector256<ulong> products, ref Vector256<ulong> multiplier, ref Vector256<ulong> result)
	{
		Vector256<ulong> c0 = Vector256<ulong>.Zero;
		Vector256<ulong> c1 = Vector256<ulong>.Zero;
		Vector256<ulong> c2 = Vector256<ulong>.Zero;
		Vector256<ulong> c3 = Vector256<ulong>.Zero;

		for (nint i = 0; i < 16; ++i)
		{
			Vector256<ulong> w = Lane(ref Unsafe.Add(ref products, i), 3);
			c0 += M(w, Unsafe.Add(ref multiplier, i));
			c1 += M(w, Unsafe.Add(ref multiplier, 16 + i));
			c2 += M(w, Unsafe.Add(ref multiplier, 32 + i));
			c3 += M(w, Unsafe.Add(ref multiplier, 48 + i));
		}

		Vector256<ulong> mask = Vector256.Create(Mask);
		Vector256<ulong> carryLow = Vector256<ulong>.Zero;
		Vector256<ulong> carryHigh = Vector256<ulong>.Zero;
		Carry(ref products, ref result, 0, c0, mask, ref carryLow, ref carryHigh, c2);
		Carry(ref products, ref result, 4, c1, mask, ref carryLow, ref carryHigh, c3);
		Wrap(ref result, carryLow, carryHigh);
	}

	// Columns 4g to 4g + 3 of lane D, from low, and 4g + 8 to 4g + 11, from high, into lane D of their limbs, carried in the chains of each half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ref Vector256<ulong> products, ref Vector256<ulong> result, nint first, Vector256<ulong> low, Vector256<ulong> mask, ref Vector256<ulong> carryLow, ref Vector256<ulong> carryHigh, Vector256<ulong> high)
	{
		CarryLimb(ref products, ref result, first, Avx2.Permute4x64(low, Aaaa), Avx2.Permute4x64(high, Aaaa), mask, ref carryLow, ref carryHigh);
		CarryLimb(ref products, ref result, first + 1, Avx2.Permute4x64(low, Bbbb), Avx2.Permute4x64(high, Bbbb), mask, ref carryLow, ref carryHigh);
		CarryLimb(ref products, ref result, first + 2, Avx2.Permute4x64(low, Cccc), Avx2.Permute4x64(high, Cccc), mask, ref carryLow, ref carryHigh);
		CarryLimb(ref products, ref result, first + 3, low, high, mask, ref carryLow, ref carryHigh);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryLimb(ref Vector256<ulong> products, ref Vector256<ulong> result, nint j, Vector256<ulong> low, Vector256<ulong> high, Vector256<ulong> mask, ref Vector256<ulong> carryLow, ref Vector256<ulong> carryHigh)
	{
		Vector256<ulong> sumLow = Blend(Unsafe.Add(ref products, j), low, LaneD) + carryLow;
		Vector256<ulong> sumHigh = Blend(Unsafe.Add(ref products, j + 8), high, LaneD) + carryHigh;
		Unsafe.Add(ref result, j) = sumLow & mask;
		Unsafe.Add(ref result, j + 8) = sumHigh & mask;
		carryLow = sumLow >> Bits;
		carryHigh = sumHigh >> Bits;
	}

	// Lane k of a vector in memory in every lane, by a load that broadcasts it rather than a shuffle.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Lane(ref Vector256<ulong> limb, int k)
	{
		return Vector256.Create(Unsafe.Add(ref Unsafe.As<Vector256<ulong>, ulong>(ref limb), k));
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
}
