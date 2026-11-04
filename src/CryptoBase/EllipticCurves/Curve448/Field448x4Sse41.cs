namespace CryptoBase.EllipticCurves.Curve448;

// The limbs of Field448x4Avx2 in 128-bit vectors, lanes A and B in one pair of sixteen and lanes C and D in another, with the same bounds. A product is two products of two lanes, each the block product of Field448x4Avx2.Product.
internal partial struct Field448x4Sse41
{
	internal Pair AB;
	internal Pair CD;

	private const int Bits = 28;
	private const ulong Mask = (1UL << Bits) - 1;

	private const ulong TwoP = (1UL << 29) - 2;
	private const ulong TwoP8 = (1UL << 29) - 4;
	private const ulong EightP = (1UL << 31) - 8;
	private const ulong EightP8 = (1UL << 31) - 16;

	private const ulong SixteenA24 = 16 * 39081;

	// The operands of Pair.Product in its scratch, in vectors, as Field448x4Avx2 lays them out for each pair; a step keeps the operands of the second pair at Second and its products at Products.
	private const int Left = 0;
	private const int Sums = 16;
	private const int Right = 24;
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

	// The factors of Field448x4Avx2.CreateMultiplier two columns to a vector: limb i of value g holds the factors of columns 2g and 2g + 1 for limb i in pair AB and those of columns 2g + 8 and 2g + 9 in pair CD.
	public static int MultiplierLength => 4;

	public static void CreateMultiplier(in Field448 u, Span<Field448x4Sse41> multiplier)
	{
		Debug.Assert(multiplier.Length is 4);

		Create(in u, in u, in u, in u, out Field448x4Sse41 limbs);
		ReadOnlySpan<Vector128<ulong>> uLimbs = MemoryMarshal.CreateReadOnlySpan(ref limbs.AB.L0, 16);
		Span<ulong> factors = MemoryMarshal.Cast<Field448x4Sse41, ulong>(multiplier);
		factors.Clear();

		for (int i = 0; i < 16; ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				ulong term = uLimbs[j].ToScalar();
				int s = i + j;

				if (s < 16)
				{
					AddFactor(factors, i, s, term);
				}
				else if (s < 24)
				{
					AddFactor(factors, i, s - 8, term);
					AddFactor(factors, i, s - 16, term);
				}
				else
				{
					AddFactor(factors, i, s - 16, 2 * term);
					AddFactor(factors, i, s - 24, term);
				}
			}
		}

		limbs.ZeroMemory();
	}

	private static void AddFactor(Span<ulong> factors, int limb, int column, ulong term)
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
			Pair.WriteOperands(ref operands, i, leftLow, leftHigh, rightLow, rightHigh);
			Pair.WriteOperands(ref second, i, leftLowCD, leftHighCD, rightLowCD, rightHighCD);
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
			Pair.PrepareRight(ref operands, i, Unsafe.Add(ref products, i), Unsafe.Add(ref products, i + 8));
			Pair.PrepareRight(ref second, i, leftLowCD, leftHighCD);
			twoPHigh = Vector128.Create(TwoP);
			eightPHigh = Vector128.Create(EightP);
		}

		Pair.CarryLeft(ref operands);
		Pair.CarryLeft(ref second);
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
	internal partial struct Pair
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

		// As Field448x4Avx2.Create.
		internal static void Create(in Field448 a, in Field448 b, out Pair result)
		{
			Vector128<ulong> mask = Vector128.Create(Mask);
			Vector128<ulong> w0 = Vector128.Create(a.L0, b.L0);
			Vector128<ulong> w1 = Vector128.Create(a.L1, b.L1);
			Vector128<ulong> w2 = Vector128.Create(a.L2, b.L2);
			Vector128<ulong> w3 = Vector128.Create(a.L3, b.L3);
			Vector128<ulong> w4 = Vector128.Create(a.L4, b.L4);
			Vector128<ulong> w5 = Vector128.Create(a.L5, b.L5);
			Vector128<ulong> w6 = Vector128.Create(a.L6, b.L6);
			Vector128<ulong> w7 = Vector128.Create(a.L7, b.L7);
			Vector128<ulong> top = w7 >> 2 * Bits;
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

		internal static void Extract(in Pair value, out Field448 a, out Field448 b)
		{
			ReadOnlySpan<Vector128<ulong>> limbs = MemoryMarshal.CreateReadOnlySpan(in value.L0, 16);
			Join(limbs, 0, out a);
			Join(limbs, 1, out b);
		}

		// As Field448x4Avx2.Join.
		private static void Join(ReadOnlySpan<Vector128<ulong>> limbs, int lane, out Field448 result)
		{
			Span<ulong> carried = stackalloc ulong[16];
			ulong carry = 0;

			for (int i = 0; i < carried.Length; ++i)
			{
				ulong sum = limbs[i].GetElement(lane) + carry;
				carried[i] = sum & Mask;
				carry = sum >> Bits;
			}

			carried[0] += carry;
			carried[8] += carry;
			result.L0 = carried[0] + (carried[1] << Bits);
			result.L1 = carried[2] + (carried[3] << Bits);
			result.L2 = carried[4] + (carried[5] << Bits);
			result.L3 = carried[6] + (carried[7] << Bits);
			result.L4 = carried[8] + (carried[9] << Bits);
			result.L5 = carried[10] + (carried[11] << Bits);
			result.L6 = carried[12] + (carried[13] << Bits);
			result.L7 = carried[14] + (carried[15] << Bits);
			carried.ZeroMemory();
		}

		// Limbs i and i + 8 of the left operand, the sum of its halves, and those of the right one as Field448x4Avx2.PrepareRight writes them.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void WriteOperands(ref Vector128<ulong> operands, nint i, Vector128<ulong> leftLow, Vector128<ulong> leftHigh, Vector128<ulong> rightLow, Vector128<ulong> rightHigh)
		{
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			Unsafe.Add(ref operands, Sums + i) = leftLow + leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void PrepareRight(ref Vector128<ulong> operands, nint i, Vector128<ulong> low, Vector128<ulong> high)
		{
			ref Vector128<ulong> right = ref Unsafe.Add(ref operands, Right);
			Vector128<ulong> sum = low + high;
			Unsafe.Add(ref right, i) = sum + high;
			Unsafe.Add(ref right, 8 + i) = sum;
			Unsafe.Add(ref right, 16 + i) = high;
			Unsafe.Add(ref right, 24 + i) = low;
		}

		// One carry from each limb of the left operand into the next, from the values before it, with the one out of limb 15 into limbs 0 and 8, and then the sums of its halves.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static void CarryLeft(ref Vector128<ulong> operands)
		{
			Vector128<ulong> mask = Vector128.Create(Mask);
			ref Vector128<ulong> left = ref Unsafe.Add(ref operands, Left);
			Vector128<ulong> carryLow = Unsafe.Add(ref left, 15) >> Bits;
			Vector128<ulong> carryHigh = (Unsafe.Add(ref left, 7) >> Bits) + carryLow;

			for (nint i = 0; i < 8; ++i)
			{
				Vector128<ulong> low = Unsafe.Add(ref left, i);
				Vector128<ulong> high = Unsafe.Add(ref left, i + 8);
				Vector128<ulong> carriedLow = (low & mask) + carryLow;
				Vector128<ulong> carriedHigh = (high & mask) + carryHigh;
				Unsafe.Add(ref left, i) = carriedLow;
				Unsafe.Add(ref left, i + 8) = carriedHigh;
				Unsafe.Add(ref operands, Sums + i) = carriedLow + carriedHigh;
				carryLow = low >> Bits;
				carryHigh = high >> Bits;
			}
		}

		// The block product of Field448x4Avx2.Product on two lanes.
		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
		internal static void Product(ref Vector128<ulong> operands, ref Vector128<ulong> result)
		{
			ref Vector128<ulong> right = ref Unsafe.Add(ref operands, Right);
			Vector128<ulong> carryLow = Vector128<ulong>.Zero;
			Vector128<ulong> carryHigh = Vector128<ulong>.Zero;

			for (nint j = 0; j < 8; j += 4)
			{
				Vector128<ulong> p0 = Vector128<ulong>.Zero, q0 = Vector128<ulong>.Zero, r0 = Vector128<ulong>.Zero;
				Vector128<ulong> p1 = Vector128<ulong>.Zero, q1 = Vector128<ulong>.Zero, r1 = Vector128<ulong>.Zero;
				Vector128<ulong> p2 = Vector128<ulong>.Zero, q2 = Vector128<ulong>.Zero, r2 = Vector128<ulong>.Zero;
				Vector128<ulong> p3 = Vector128<ulong>.Zero, q3 = Vector128<ulong>.Zero, r3 = Vector128<ulong>.Zero;
				ref Vector128<ulong> x = ref Unsafe.Add(ref operands, Left);
				ref Vector128<ulong> y = ref Unsafe.Add(ref right, j + 8);

				for (nint k = 0; k < 8; ++k)
				{
					Vector128<ulong> low = x;
					Vector128<ulong> high = Unsafe.Add(ref x, 8);
					Vector128<ulong> sum = Unsafe.Add(ref x, 16);
					Accumulate(ref y, 0, low, high, sum, ref p0, ref q0, ref r0);
					Accumulate(ref y, 1, low, high, sum, ref p1, ref q1, ref r1);
					Accumulate(ref y, 2, low, high, sum, ref p2, ref q2, ref r2);
					Accumulate(ref y, 3, low, high, sum, ref p3, ref q3, ref r3);
					x = ref Unsafe.Add(ref x, 1);
					y = ref Unsafe.Subtract(ref y, 1);
				}

				Column(ref result, j, p0, q0, r0, ref carryLow, ref carryHigh);
				Column(ref result, j + 1, p1, q1, r1, ref carryLow, ref carryHigh);
				Column(ref result, j + 2, p2, q2, r2, ref carryLow, ref carryHigh);
				Column(ref result, j + 3, p3, q3, r3, ref carryLow, ref carryHigh);
			}

			Wrap(ref result, carryLow, carryHigh);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Accumulate(ref Vector128<ulong> y, nint c, Vector128<ulong> low, Vector128<ulong> high, Vector128<ulong> sum, ref Vector128<ulong> p, ref Vector128<ulong> q, ref Vector128<ulong> r)
		{
			p += M(low, Unsafe.Add(ref y, c + 16));
			q += M(high, Unsafe.Add(ref y, c + 8));
			r += M(sum, Unsafe.Add(ref y, c));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Column(ref Vector128<ulong> result, nint j, Vector128<ulong> p, Vector128<ulong> q, Vector128<ulong> r, ref Vector128<ulong> carryLow, ref Vector128<ulong> carryHigh)
		{
			Vector128<ulong> mask = Vector128.Create(Mask);
			Vector128<ulong> low = p + q + carryLow;
			Vector128<ulong> high = r - p + carryHigh;
			Unsafe.Add(ref result, j) = low & mask;
			Unsafe.Add(ref result, j + 8) = high & mask;
			carryLow = low >> Bits;
			carryHigh = high >> Bits;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void Wrap(ref Vector128<ulong> limbs, Vector128<ulong> carryLow, Vector128<ulong> carryHigh)
		{
			Vector128<ulong> mask = Vector128.Create(Mask);
			Vector128<ulong> low = limbs + carryHigh;
			Vector128<ulong> high = Unsafe.Add(ref limbs, 8) + carryLow + carryHigh;
			limbs = low & mask;
			Unsafe.Add(ref limbs, 1) += low >> Bits;
			Unsafe.Add(ref limbs, 8) = high & mask;
			Unsafe.Add(ref limbs, 9) += high >> Bits;
		}
	}
}
