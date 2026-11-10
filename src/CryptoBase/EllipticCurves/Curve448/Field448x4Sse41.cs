using static CryptoBase.EllipticCurves.Curve448.Field448Blocks<System.Runtime.Intrinsics.Vector128<ulong>, CryptoBase.EllipticCurves.Curve448.Field448Vector128>;

namespace CryptoBase.EllipticCurves.Curve448;

// The limbs of Field448x4Avx2 in 128-bit vectors, lanes A and B in one pair of sixteen and lanes C and D in another, with the same bounds. A product is two products of two lanes, each the block product of Field448Blocks.Product.
internal partial struct Field448x4Sse41
{
	internal Pair AB;
	internal Pair CD;

	private const ulong EightP = (1UL << 31) - 8;
	private const ulong EightP8 = (1UL << 31) - 16;

	private const ulong SixteenA24 = 16 * 39081;

	// A step keeps the operands of Pair.Product for the second pair at Second, laid out as those of the first, and its products at Products.
	private const int Second = 56;
	private const int Products = 112;

	// pblendw mask of the second 64-bit lane.
	private const byte SecondLane = 0xF0;

	// pshufd control that swaps the two 64-bit lanes.
	private const byte SwapLanes = 0b01_00_11_10;

	public static bool IsSupported => Sse41.IsSupported;

	public static void Create(in Field448 a, in Field448 b, in Field448 c, in Field448 d, out Field448x4Sse41 result)
	{
		Pair.Create(in a, in b, out result.AB);
		Pair.Create(in c, in d, out result.CD);
	}

	public static void Extract(in Field448x4Sse41 value, out Field448 a, out Field448 b, out Field448 c, out Field448 d)
	{
		Pair.Extract(in value.AB, out a, out b);
		Pair.Extract(in value.CD, out c, out d);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field448x4Sse41 value)
	{
		Vector128<ulong> select = Vector128.Create(mask);
		ref Vector128<ulong> ab = ref value.AB.L0;
		ref Vector128<ulong> cd = ref value.CD.L0;

		for (nint i = 0; i < 16; ++i)
		{
			SwapUnder(select, ref Unsafe.Add(ref ab, i), ref Unsafe.Add(ref cd, i));
		}
	}

	// The factors of IField448x4.CreateMultiplier two columns to a vector: limb i of value g holds the factors of columns 2g and 2g + 1 for limb i in pair AB and those of columns 2g + 8 and 2g + 9 in pair CD.
	public static int MultiplierLength => 4;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ulong LaneALimb(in Field448x4Sse41 value, int limb)
	{
		return Unsafe.Add(ref Unsafe.AsRef(in value.AB.L0), limb).ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void AddFactor(Span<ulong> factors, int limb, int column, ulong term)
	{
		factors[(column & 7) >> 1 << 6 | column >> 3 << 5 | limb << 1 | column & 1] += term;
	}

	// Operands, products and their columns in five values, and the doubled operands of a square in a sixth.
	public static int ScratchLength => 6;

	// The products and operands of Field448x4Avx2.LadderStep, pair by pair.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderStep(ref Field448x4Sse41 state, ulong swap, in Field448x4Sse41 multiplier, ref Field448x4Sse41 scratch)
	{
		ref Vector128<ulong> operands = ref scratch.AB.L0;
		ref Vector128<ulong> products = ref Unsafe.Add(ref operands, Products);
		PrepareLadder(ref state, swap, ref operands);
		Pair.Product(ref operands, ref products);
		Pair.Product(ref Unsafe.Add(ref operands, Second), ref Unsafe.Add(ref products, 16));
		FinishLadder(ref products, ref operands);
		Pair.Product(ref operands, ref products);
		Pair.Product(ref Unsafe.Add(ref operands, Second), ref Unsafe.Add(ref products, 16));
		MultiplyLaneD(ref products, ref Unsafe.AsRef(in multiplier.AB.L0), ref state, ref operands);
	}

	// The operands of the first product, as Field448x4Avx2.PrepareLadder takes them: (A, x2) and (D, C) on the left, (A, z2) and (A, B) on the right, from (x2, z2) and (x3, z3) exchanged under the swap.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(ref Field448x4Sse41 state, ulong swap, ref Vector128<ulong> operands)
	{
		Vector128<ulong> select = Vector128.Create(swap);
		ref Vector128<ulong> ab = ref state.AB.L0;
		ref Vector128<ulong> cd = ref state.CD.L0;
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareLadder(Unsafe.Add(ref ab, i), Unsafe.Add(ref cd, i), select, Vector128.Create(TwoP), out Vector128<ulong> leftLow, out Vector128<ulong> leftLowCD, out Vector128<ulong> rightLow, out Vector128<ulong> rightLowCD);
			PrepareLadder(Unsafe.Add(ref ab, i + 8), Unsafe.Add(ref cd, i + 8), select, twoPHigh, out Vector128<ulong> leftHigh, out Vector128<ulong> leftHighCD, out Vector128<ulong> rightHigh, out Vector128<ulong> rightHighCD);
			WriteOperands(ref operands, i, leftLow, leftHigh, rightLow, rightHigh);
			WriteOperands(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
			twoPHigh = Vector128.Create(TwoP);
		}
	}

	// As above for one limb of each pair.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> select, Vector128<ulong> twoP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<ulong> rightAB, out Vector128<ulong> rightCD)
	{
		SwapUnder(select, ref ab, ref cd);
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);

		// Lane A of each holds A, B, C and D.
		Vector128<ulong> a = ab + swappedAB;
		Vector128<ulong> b = ab + twoP - swappedAB;
		Vector128<ulong> c = cd + swappedCD;
		Vector128<ulong> d = cd + twoP - swappedCD;
		leftAB = Blend(a, swappedAB);
		leftCD = Sse2.UnpackLow(d, c);
		rightAB = Blend(a, ab);
		rightCD = Sse2.UnpackLow(a, b);
	}

	// The operands of the second product, as Field448x4Avx2.FinishLadder takes them: from (AA, w) and (DA, CB), the left one (AA + 8p − 4w, 4AA + 16a24·w) and (DA + CB, DA + 2p − CB), carried once from each limb into the next, and the right one (AA, w) and (DA + CB, DA + 2p − CB).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(ref Vector128<ulong> products, ref Vector128<ulong> operands)
	{
		ref Vector128<ulong> second = ref Unsafe.Add(ref operands, Second);
		ref Vector128<ulong> productsCD = ref Unsafe.Add(ref products, 16);
		Vector128<ulong> twoPHigh = Vector128.Create(TwoP8);
		Vector128<ulong> eightPHigh = Vector128.Create(EightP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishLadder(Unsafe.Add(ref products, i), Unsafe.Add(ref productsCD, i), Vector128.Create(TwoP), Vector128.Create(EightP), out Vector128<ulong> leftLow, out Vector128<ulong> leftLowCD);
			FinishLadder(Unsafe.Add(ref products, i + 8), Unsafe.Add(ref productsCD, i + 8), twoPHigh, eightPHigh, out Vector128<ulong> leftHigh, out Vector128<ulong> leftHighCD);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			Unsafe.Add(ref second, Left + i) = leftLowCD;
			Unsafe.Add(ref second, Left + i + 8) = leftHighCD;
			PrepareRight(ref operands, i, Unsafe.Add(ref products, i), Unsafe.Add(ref products, i + 8));
			PrepareRight(ref second, i, leftLowCD, leftHighCD);
			twoPHigh = Vector128.Create(TwoP);
			eightPHigh = Vector128.Create(EightP);
		}

		CarryLeft(ref operands);
		CarryLeft(ref second);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector128<ulong> ab, Vector128<ulong> cd, Vector128<ulong> twoP, Vector128<ulong> eightP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD)
	{
		Vector128<ulong> swappedAB = Swap(ab);
		Vector128<ulong> swappedCD = Swap(cd);
		Vector128<ulong> four = swappedAB << 2;
		leftAB = Blend(ab + eightP - four, four + M(ab, Vector128.Create(0, SixteenA24)));
		leftCD = Blend(cd + swappedCD, swappedCD + twoP - cd);
	}

	// The columns of lane D of the products times u, two at a time: lane D, the second lane of pair CD, in both lanes times the factors of columns 2g and 2g + 1 and of columns 2g + 8 and 2g + 9, in two rounds of carries in that form, through columns in the scratch; then column k goes into lane D of limb k.
	// ReSharper disable once RedundantAssignment
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyLaneD(ref Vector128<ulong> products, ref Vector128<ulong> multiplier, ref Field448x4Sse41 state, ref Vector128<ulong> columns)
	{
		ref Vector128<ulong> cd = ref Unsafe.Add(ref products, 16);
		Vector128<ulong> c0 = Vector128<ulong>.Zero, c1 = Vector128<ulong>.Zero, c2 = Vector128<ulong>.Zero, c3 = Vector128<ulong>.Zero;
		Vector128<ulong> c4 = Vector128<ulong>.Zero, c5 = Vector128<ulong>.Zero, c6 = Vector128<ulong>.Zero, c7 = Vector128<ulong>.Zero;
		ref Vector128<ulong> factors = ref multiplier;

		for (nint i = 0; i < 16; ++i)
		{
			Vector128<ulong> w = Vector128.Create(Unsafe.Add(ref Unsafe.As<Vector128<ulong>, ulong>(ref cd), 2 * i + 1));
			c0 += M(w, factors);
			c4 += M(w, Unsafe.Add(ref factors, 16));
			c1 += M(w, Unsafe.Add(ref factors, 32));
			c5 += M(w, Unsafe.Add(ref factors, 48));
			c2 += M(w, Unsafe.Add(ref factors, 64));
			c6 += M(w, Unsafe.Add(ref factors, 80));
			c3 += M(w, Unsafe.Add(ref factors, 96));
			c7 += M(w, Unsafe.Add(ref factors, 112));
			factors = ref Unsafe.Add(ref factors, 1);
		}

		CarryColumns(ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		CarryColumns(ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		columns = c0;
		Unsafe.Add(ref columns, 1) = c1;
		Unsafe.Add(ref columns, 2) = c2;
		Unsafe.Add(ref columns, 3) = c3;
		Unsafe.Add(ref columns, 4) = c4;
		Unsafe.Add(ref columns, 5) = c5;
		Unsafe.Add(ref columns, 6) = c6;
		Unsafe.Add(ref columns, 7) = c7;
		ref ulong column = ref Unsafe.As<Vector128<ulong>, ulong>(ref columns);
		ref Vector128<ulong> resultAB = ref state.AB.L0;
		ref Vector128<ulong> resultCD = ref state.CD.L0;

		for (nint k = 0; k < 16; ++k)
		{
			Unsafe.Add(ref resultAB, k) = Unsafe.Add(ref products, k);
			Unsafe.Add(ref resultCD, k) = Blend(Unsafe.Add(ref cd, k), Vector128.Create(Unsafe.Add(ref column, k)));
		}
	}

	// One carry from each of the columns 0 to 15, two to a vector, into the next, the one out of column 15 into columns 0 and 8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryColumns(ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> c2, ref Vector128<ulong> c3, ref Vector128<ulong> c4, ref Vector128<ulong> c5, ref Vector128<ulong> c6, ref Vector128<ulong> c7)
	{
		Vector128<ulong> mask = Vector128.Create(Mask);
		Vector128<ulong> carry0 = c0 >> Bits;
		Vector128<ulong> carry1 = c1 >> Bits;
		Vector128<ulong> carry2 = c2 >> Bits;
		Vector128<ulong> carry3 = c3 >> Bits;
		Vector128<ulong> carry4 = c4 >> Bits;
		Vector128<ulong> carry5 = c5 >> Bits;
		Vector128<ulong> carry6 = c6 >> Bits;
		Vector128<ulong> carry7 = c7 >> Bits;
		c0 = (c0 & mask) + Previous(carry7, carry0);
		c1 = (c1 & mask) + Previous(carry0, carry1);
		c2 = (c2 & mask) + Previous(carry1, carry2);
		c3 = (c3 & mask) + Previous(carry2, carry3);
		c4 = (c4 & mask) + Previous(carry3, carry4) + Previous(carry7, Vector128<ulong>.Zero);
		c5 = (c5 & mask) + Previous(carry4, carry5);
		c6 = (c6 & mask) + Previous(carry5, carry6);
		c7 = (c7 & mask) + Previous(carry6, carry7);
	}

	// The second lane of before, then the first of value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Previous(Vector128<ulong> before, Vector128<ulong> value)
	{
		return Sse2.Shuffle(before.AsDouble(), value.AsDouble(), 0b01).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SwapUnder(Vector128<ulong> mask, ref Vector128<ulong> first, ref Vector128<ulong> second)
	{
		Vector128<ulong> difference = (first ^ second) & mask;
		first ^= difference;
		second ^= difference;
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
		return Sse41.Blend(left.AsUInt16(), right.AsUInt16(), SecondLane).AsUInt64();
	}

	// The low 32 bits of each 64-bit lane multiplied.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> M(Vector128<ulong> x, Vector128<ulong> y)
	{
		return Sse2.Multiply(x.AsUInt32(), y.AsUInt32());
	}

	// Two of the four lanes: limb i of each in vector i.
	internal partial struct Pair : IField448Lanes<Pair>
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
		internal Vector128<ulong> L10;
		internal Vector128<ulong> L11;
		internal Vector128<ulong> L12;
		internal Vector128<ulong> L13;
		internal Vector128<ulong> L14;
		internal Vector128<ulong> L15;

		internal static void Create(in Field448 a, in Field448 b, out Pair result)
		{
			Unsafe.SkipInit(out result);
			Field448.ToRadix28(Vector128.Create(a.L0, b.L0), Vector128.Create(a.L1, b.L1), Vector128.Create(a.L2, b.L2), Vector128.Create(a.L3, b.L3), Vector128.Create(a.L4, b.L4), Vector128.Create(a.L5, b.L5), Vector128.Create(a.L6, b.L6), Vector128.Create(a.L7, b.L7), ref result.L0);
		}

		internal static void Extract(in Pair value, out Field448 a, out Field448 b)
		{
			Field448.FromRadix28(in value, 0, out a);
			Field448.FromRadix28(in value, 1, out b);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ulong Limb(in Pair value, int limb, int lane)
		{
			return Unsafe.Add(ref Unsafe.AsRef(in value.L0), limb).GetElement(lane);
		}

		// The block product of Field448Blocks.Product on two lanes.
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void Product(ref Vector128<ulong> operands, ref Vector128<ulong> result)
		{
			Field448Blocks<Vector128<ulong>, Field448Vector128>.Product(ref operands, ref result);
		}
	}
}
