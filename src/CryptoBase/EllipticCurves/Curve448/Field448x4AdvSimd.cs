namespace CryptoBase.EllipticCurves.Curve448;

// The limbs of Field448x4Avx2 in 128-bit vectors of 32-bit lanes: vector i holds limb i of lanes A, B, C, D, each of which fits 32 bits. umlal multiplies lanes A and B into 64-bit lanes and umlal2 lanes C and D, so the columns of a product take two vectors each, and its limbs narrow back once carried. The members take and give the bounds of Field448x4Avx2.
internal partial struct Field448x4AdvSimd
{
	internal Vector128<uint> L0;
	// ReSharper disable UnassignedField.Compiler
	internal Vector128<uint> L1;
	internal Vector128<uint> L2;
	internal Vector128<uint> L3;
	internal Vector128<uint> L4;
	internal Vector128<uint> L5;
	internal Vector128<uint> L6;
	internal Vector128<uint> L7;
	internal Vector128<uint> L8;
	internal Vector128<uint> L9;
	internal Vector128<uint> L10;
	internal Vector128<uint> L11;
	internal Vector128<uint> L12;
	internal Vector128<uint> L13;
	internal Vector128<uint> L14;
	internal Vector128<uint> L15;
	// ReSharper restore UnassignedField.Compiler

	private const int Bits = 28;
	private const uint Mask = (1u << Bits) - 1;

	private const uint TwoP = (1u << 29) - 2;
	private const uint TwoP8 = (1u << 29) - 4;
	private const uint EightP = (1u << 31) - 8;
	private const uint EightP8 = (1u << 31) - 16;

	private const uint SixteenA24 = 16 * 39081;

	// The operands of Product in its scratch, in vectors, as Field448x4Avx2 lays them out; a step keeps its products at Products.
	private const int Left = 0;
	private const int Sums = 16;
	private const int Right = 24;
	private const int Products = 56;

	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	// As Field448x4Avx2.Create, lanes A and B in one vector of 64-bit lanes and C and D in another.
	public static void Create(in Field448 a, in Field448 b, in Field448 c, in Field448 d, out Field448x4AdvSimd result)
	{
		Split(Vector128.Create(a.L0, b.L0), Vector128.Create(a.L1, b.L1), Vector128.Create(a.L2, b.L2), Vector128.Create(a.L3, b.L3), Vector128.Create(a.L4, b.L4), Vector128.Create(a.L5, b.L5), Vector128.Create(a.L6, b.L6), Vector128.Create(a.L7, b.L7), out Wide low);
		Split(Vector128.Create(c.L0, d.L0), Vector128.Create(c.L1, d.L1), Vector128.Create(c.L2, d.L2), Vector128.Create(c.L3, d.L3), Vector128.Create(c.L4, d.L4), Vector128.Create(c.L5, d.L5), Vector128.Create(c.L6, d.L6), Vector128.Create(c.L7, d.L7), out Wide high);
		Unsafe.SkipInit(out result);
		ref Vector128<uint> limbs = ref result.L0;

		for (int i = 0; i < 16; ++i)
		{
			Unsafe.Add(ref limbs, i) = Vector128.Narrow(low[i], high[i]);
		}

		low.ZeroMemory();
		high.ZeroMemory();
	}

	// The limbs of two lanes from their 56-bit limbs w0 to w7, carried as Field448x4Avx2.Create carries them.
	private static void Split(Vector128<ulong> w0, Vector128<ulong> w1, Vector128<ulong> w2, Vector128<ulong> w3, Vector128<ulong> w4, Vector128<ulong> w5, Vector128<ulong> w6, Vector128<ulong> w7, out Wide result)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		Vector128<ulong> top = w7 >> 2 * Bits;
		Unsafe.SkipInit(out result);
		result[0] = (w0 & mask) + top;
		result[1] = w0 >> Bits & mask;
		result[2] = (w1 & mask) + (w0 >> 2 * Bits);
		result[3] = w1 >> Bits & mask;
		result[4] = (w2 & mask) + (w1 >> 2 * Bits);
		result[5] = w2 >> Bits & mask;
		result[6] = (w3 & mask) + (w2 >> 2 * Bits);
		result[7] = w3 >> Bits & mask;
		result[8] = (w4 & mask) + (w3 >> 2 * Bits) + top;
		result[9] = w4 >> Bits & mask;
		result[10] = (w5 & mask) + (w4 >> 2 * Bits);
		result[11] = w5 >> Bits & mask;
		result[12] = (w6 & mask) + (w5 >> 2 * Bits);
		result[13] = w6 >> Bits & mask;
		result[14] = (w7 & mask) + (w6 >> 2 * Bits);
		result[15] = w7 >> Bits & mask;
	}

	public static void Extract(in Field448x4AdvSimd value, out Field448 a, out Field448 b, out Field448 c, out Field448 d)
	{
		ReadOnlySpan<Vector128<uint>> limbs = MemoryMarshal.CreateReadOnlySpan(in value.L0, 16);
		Join(limbs, 0, out a);
		Join(limbs, 1, out b);
		Join(limbs, 2, out c);
		Join(limbs, 3, out d);
	}

	// As Field448x4Avx2.Join.
	private static void Join(ReadOnlySpan<Vector128<uint>> limbs, int lane, out Field448 result)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ConditionalSwapHalves(ulong mask, ref Field448x4AdvSimd value)
	{
		Vector128<uint> select = Vector128.Create((uint)mask);
		ref Vector128<uint> limbs = ref value.L0;

		for (nint i = 0; i < 16; ++i)
		{
			ref Vector128<uint> limb = ref Unsafe.Add(ref limbs, i);
			limb = Vector128.ConditionalSelect(select, AdvSimd.ExtractVector128(limb, limb, 2), limb);
		}
	}

	// The factors of Field448x4Avx2.CreateMultiplier, in 32-bit lanes: lane l of limb i of value g holds the factor of column 4g + l for limb i.
	public static int MultiplierLength => 4;

	public static void CreateMultiplier(in Field448 u, Span<Field448x4AdvSimd> multiplier)
	{
		Debug.Assert(multiplier.Length is 4);

		Create(in u, in u, in u, in u, out Field448x4AdvSimd limbs);
		ReadOnlySpan<Vector128<uint>> uLimbs = MemoryMarshal.CreateReadOnlySpan(ref limbs.L0, 16);
		Span<uint> factors = MemoryMarshal.Cast<Field448x4AdvSimd, uint>(multiplier);
		factors.Clear();

		for (int i = 0; i < 16; ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				uint term = uLimbs[j].ToScalar();
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

	private static void AddFactor(Span<uint> factors, int limb, int column, uint term)
	{
		factors[(column >> 2) * 64 + limb * 4 + (column & 3)] += term;
	}

	// The operands and the products of a step in five values, and the doubled operand of a square in a sixth.
	public static int ScratchLength => 6;

	// The products and operands of Field448x4Avx2.LadderStep.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	public static void LadderStep(ref Field448x4AdvSimd state, ulong swap, in Field448x4AdvSimd multiplier, ref Field448x4AdvSimd scratch)
	{
		ref Vector128<uint> operands = ref scratch.L0;
		ref Vector128<uint> products = ref Unsafe.Add(ref operands, Products);
		PrepareLadder(ref state.L0, swap, ref operands);
		Product(ref operands, ref products);
		FinishLadder(ref products, ref operands);
		Product(ref operands, ref products);
		MultiplyLaneD(ref products, ref Unsafe.AsRef(in multiplier.L0), ref state.L0);
	}

	// The operands of the first product, as Field448x4Avx2.PrepareLadder takes them, with the lanes that the swap selects by the indices of a tbl, which takes the same time for every index.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(ref Vector128<uint> state, ulong swap, ref Vector128<uint> operands)
	{
		Vector128<byte> flip = Vector128.Create((byte)(swap & 8));
		Vector128<byte> xs = Vector128.Create((byte)0, 1, 2, 3, 0, 1, 2, 3, 8, 9, 10, 11, 8, 9, 10, 11) ^ flip;
		Vector128<byte> zs = Vector128.Create((byte)4, 5, 6, 7, 4, 5, 6, 7, 12, 13, 14, 15, 12, 13, 14, 15) ^ flip;
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);

		for (nint i = 0; i < 8; ++i)
		{
			PrepareLadder(Unsafe.Add(ref state, i), xs, zs, Vector128.Create(TwoP), out Vector128<uint> leftLow, out Vector128<uint> rightLow);
			PrepareLadder(Unsafe.Add(ref state, i + 8), xs, zs, twoPHigh, out Vector128<uint> leftHigh, out Vector128<uint> rightHigh);
			Unsafe.Add(ref operands, Left + i) = leftLow;
			Unsafe.Add(ref operands, Left + i + 8) = leftHigh;
			Unsafe.Add(ref operands, Sums + i) = leftLow + leftHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			twoPHigh = Vector128.Create(TwoP);
		}
	}

	// (x2, x2, x3, x3) + (z2, 2p − z2, z3, 2p − z3) = (A, B, C, D), then (A, x2, D, C) and (A, z2, A, B), each a tbl of the sums with lane B selected from x or z.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareLadder(Vector128<uint> limb, Vector128<byte> xs, Vector128<byte> zs, Vector128<uint> twoP, out Vector128<uint> left, out Vector128<uint> right)
	{
		Vector128<uint> laneB = Vector128.Create(0, uint.MaxValue, 0, 0);
		Vector128<uint> x = AdvSimd.Arm64.VectorTableLookup(limb.AsByte(), xs).AsUInt32();
		Vector128<uint> z = AdvSimd.Arm64.VectorTableLookup(limb.AsByte(), zs).AsUInt32();
		Vector128<byte> sums = (x + Vector128.ConditionalSelect(Vector128.Create(0, uint.MaxValue, 0, uint.MaxValue), twoP - z, z)).AsByte();
		left = Vector128.ConditionalSelect(laneB, x, AdvSimd.Arm64.VectorTableLookup(sums, Vector128.Create((byte)0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 8, 9, 10, 11)).AsUInt32());
		right = Vector128.ConditionalSelect(laneB, z, AdvSimd.Arm64.VectorTableLookup(sums, Vector128.Create((byte)0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)).AsUInt32());
	}

	// The operands of the second product, as Field448x4Avx2.FinishLadder takes them. The left one carries in 64-bit lanes, as 16a24·w in lane B is below 2^47.3; limbs 7 and 15 go first, as limbs 0 and 8 take their carries.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(ref Vector128<uint> products, ref Vector128<uint> operands)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		FinishLadder(Unsafe.Add(ref products, 7), Vector128.Create(TwoP), Vector128.Create(EightP), out Vector128<ulong> lowerAB, out Vector128<ulong> lowerCD, out _);
		FinishLadder(Unsafe.Add(ref products, 15), Vector128.Create(TwoP), Vector128.Create(EightP), out Vector128<ulong> upperAB, out Vector128<ulong> upperCD, out _);
		Vector128<ulong> carryLowAB = upperAB >> Bits;
		Vector128<ulong> carryLowCD = upperCD >> Bits;
		Vector128<ulong> carryHighAB = (lowerAB >> Bits) + carryLowAB;
		Vector128<ulong> carryHighCD = (lowerCD >> Bits) + carryLowCD;
		Vector128<uint> twoPHigh = Vector128.Create(TwoP8);
		Vector128<uint> eightPHigh = Vector128.Create(EightP8);

		for (nint i = 0; i < 8; ++i)
		{
			FinishLadder(Unsafe.Add(ref products, i), Vector128.Create(TwoP), Vector128.Create(EightP), out Vector128<ulong> lowAB, out Vector128<ulong> lowCD, out Vector128<uint> rightLow);
			FinishLadder(Unsafe.Add(ref products, i + 8), twoPHigh, eightPHigh, out Vector128<ulong> highAB, out Vector128<ulong> highCD, out Vector128<uint> rightHigh);
			Vector128<uint> carriedLow = Vector128.Narrow((lowAB & mask) + carryLowAB, (lowCD & mask) + carryLowCD);
			Vector128<uint> carriedHigh = Vector128.Narrow((highAB & mask) + carryHighAB, (highCD & mask) + carryHighCD);
			Unsafe.Add(ref operands, Left + i) = carriedLow;
			Unsafe.Add(ref operands, Left + i + 8) = carriedHigh;
			Unsafe.Add(ref operands, Sums + i) = carriedLow + carriedHigh;
			PrepareRight(ref operands, i, rightLow, rightHigh);
			carryLowAB = lowAB >> Bits;
			carryLowCD = lowCD >> Bits;
			carryHighAB = highAB >> Bits;
			carryHighCD = highCD >> Bits;
			twoPHigh = Vector128.Create(TwoP);
			eightPHigh = Vector128.Create(EightP);
		}
	}

	// From (AA, w, DA, CB) and its swap (w, AA, CB, DA): the left operand (AA + 8p − 4w, 4AA + 16a24·w, DA + CB, DA + 2p − CB) in two vectors of 64-bit lanes, and the right one, (AA, w, DA + CB, DA + 2p − CB).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void FinishLadder(Vector128<uint> limb, Vector128<uint> twoP, Vector128<uint> eightP, out Vector128<ulong> leftAB, out Vector128<ulong> leftCD, out Vector128<uint> right)
	{
		Vector128<uint> swapped = AdvSimd.ReverseElement32(limb.AsUInt64()).AsUInt32();
		Vector128<uint> four = swapped << 2;
		Vector128<uint> tail = Vector128.ConditionalSelect(Vector128.Create(0, 0, 0, uint.MaxValue), swapped + twoP - limb, limb + swapped);
		Vector128<uint> first = Vector128.ConditionalSelect(Vector128.Create(uint.MaxValue, 0, 0, 0), limb + eightP - four, four);
		leftAB = AdvSimd.MultiplyWideningLowerAndAdd(Vector128.WidenLower(first), limb.GetLower(), Vector64.Create(0, SixteenA24));
		leftCD = Vector128.WidenUpper(tail);
		right = Vector128.ConditionalSelect(Vector128.Create(0, 0, uint.MaxValue, uint.MaxValue), tail, limb);
	}

	// Writes limbs i and i + 8 of y in the form that Field448x4Avx2.Product takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrepareRight(ref Vector128<uint> operands, nint i, Vector128<uint> low, Vector128<uint> high)
	{
		ref Vector128<uint> right = ref Unsafe.Add(ref operands, Right);
		Vector128<uint> sum = low + high;
		Unsafe.Add(ref right, i) = sum + high;
		Unsafe.Add(ref right, 8 + i) = sum;
		Unsafe.Add(ref right, 16 + i) = high;
		Unsafe.Add(ref right, 24 + i) = low;
	}

	// The products of Field448x4Avx2.Product, lanes A and B and lanes C and D by umlal into separate columns of 64-bit lanes, two columns at a time. Each operand reads its halves as two 64-bit vectors, as taking the lower half of a 128-bit vector costs a move.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Product(ref Vector128<uint> operands, ref Vector128<uint> result)
	{
		ref Vector64<uint> right = ref Halves(ref Unsafe.Add(ref operands, Right));
		Vector128<ulong> carryLow = Vector128<ulong>.Zero;
		Vector128<ulong> carryLowUpper = Vector128<ulong>.Zero;
		Vector128<ulong> carryHigh = Vector128<ulong>.Zero;
		Vector128<ulong> carryHighUpper = Vector128<ulong>.Zero;

		for (nint j = 0; j < 8; j += 2)
		{
			Vector128<ulong> p0 = Vector128<ulong>.Zero, p0Upper = Vector128<ulong>.Zero, q0 = Vector128<ulong>.Zero, q0Upper = Vector128<ulong>.Zero, r0 = Vector128<ulong>.Zero, r0Upper = Vector128<ulong>.Zero;
			Vector128<ulong> p1 = Vector128<ulong>.Zero, p1Upper = Vector128<ulong>.Zero, q1 = Vector128<ulong>.Zero, q1Upper = Vector128<ulong>.Zero, r1 = Vector128<ulong>.Zero, r1Upper = Vector128<ulong>.Zero;
			ref Vector64<uint> x = ref Halves(ref Unsafe.Add(ref operands, Left));

			// y_n for n = j + c − k + 8 lies at vector c of y, halves 2c and 2c + 1.
			ref Vector64<uint> y = ref Unsafe.Add(ref right, 2 * (j + 8));

			for (nint k = 0; k < 8; ++k)
			{
				Vector64<uint> low = x;
				Vector64<uint> lowUpper = Unsafe.Add(ref x, 1);
				Vector64<uint> high = Unsafe.Add(ref x, 16);
				Vector64<uint> highUpper = Unsafe.Add(ref x, 17);
				Vector64<uint> sum = Unsafe.Add(ref x, 32);
				Vector64<uint> sumUpper = Unsafe.Add(ref x, 33);
				Accumulate(ref y, 0, low, lowUpper, high, highUpper, sum, sumUpper, ref p0, ref p0Upper, ref q0, ref q0Upper, ref r0, ref r0Upper);
				Accumulate(ref y, 2, low, lowUpper, high, highUpper, sum, sumUpper, ref p1, ref p1Upper, ref q1, ref q1Upper, ref r1, ref r1Upper);
				x = ref Unsafe.Add(ref x, 2);
				y = ref Unsafe.Subtract(ref y, 2);
			}

			Column(ref result, j, p0 + q0, p0Upper + q0Upper, r0 - p0, r0Upper - p0Upper, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
			Column(ref result, j + 1, p1 + q1, p1Upper + q1Upper, r1 - p1, r1Upper - p1Upper, ref carryLow, ref carryLowUpper, ref carryHigh, ref carryHighUpper);
		}

		Wrap(ref result, carryLow, carryLowUpper, carryHigh, carryHighUpper);
	}

	// x_k times sum_n, high_n and low_n at half h of y, lanes A and B into p, q and r and lanes C and D into their upper counterparts.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Accumulate(ref Vector64<uint> y, nint h, Vector64<uint> low, Vector64<uint> lowUpper, Vector64<uint> high, Vector64<uint> highUpper, Vector64<uint> sum, Vector64<uint> sumUpper, ref Vector128<ulong> p, ref Vector128<ulong> pUpper, ref Vector128<ulong> q, ref Vector128<ulong> qUpper, ref Vector128<ulong> r, ref Vector128<ulong> rUpper)
	{
		p = AdvSimd.MultiplyWideningLowerAndAdd(p, low, Unsafe.Add(ref y, h + 32));
		pUpper = AdvSimd.MultiplyWideningLowerAndAdd(pUpper, lowUpper, Unsafe.Add(ref y, h + 33));
		q = AdvSimd.MultiplyWideningLowerAndAdd(q, high, Unsafe.Add(ref y, h + 16));
		qUpper = AdvSimd.MultiplyWideningLowerAndAdd(qUpper, highUpper, Unsafe.Add(ref y, h + 17));
		r = AdvSimd.MultiplyWideningLowerAndAdd(r, sum, Unsafe.Add(ref y, h));
		rUpper = AdvSimd.MultiplyWideningLowerAndAdd(rUpper, sumUpper, Unsafe.Add(ref y, h + 1));
	}

	// The 64-bit halves of the vectors from value on.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref Vector64<uint> Halves(ref Vector128<uint> value)
	{
		return ref Unsafe.As<Vector128<uint>, Vector64<uint>>(ref value);
	}

	// Limbs j and j + 8 from columns low and high of lanes A and B and their upper counterparts of lanes C and D, with the carries into them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Column(ref Vector128<uint> result, nint j, Vector128<ulong> low, Vector128<ulong> lowUpper, Vector128<ulong> high, Vector128<ulong> highUpper, ref Vector128<ulong> carryLow, ref Vector128<ulong> carryLowUpper, ref Vector128<ulong> carryHigh, ref Vector128<ulong> carryHighUpper)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		low += carryLow;
		lowUpper += carryLowUpper;
		high += carryHigh;
		highUpper += carryHighUpper;
		Unsafe.Add(ref result, j) = Vector128.Narrow(low & mask, lowUpper & mask);
		Unsafe.Add(ref result, j + 8) = Vector128.Narrow(high & mask, highUpper & mask);
		carryLow = low >> Bits;
		carryLowUpper = lowUpper >> Bits;
		carryHigh = high >> Bits;
		carryHighUpper = highUpper >> Bits;
	}

	// As Field448x4Avx2.Wrap, the carries in 64-bit lanes added to limbs 0 and 8 widened.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Wrap(ref Vector128<uint> limbs, Vector128<ulong> carryLow, Vector128<ulong> carryLowUpper, Vector128<ulong> carryHigh, Vector128<ulong> carryHighUpper)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		Vector128<uint> zero = limbs;
		Vector128<uint> eight = Unsafe.Add(ref limbs, 8);
		Vector128<ulong> low = Vector128.WidenLower(zero) + carryHigh;
		Vector128<ulong> lowUpper = Vector128.WidenUpper(zero) + carryHighUpper;
		Vector128<ulong> high = Vector128.WidenLower(eight) + carryLow + carryHigh;
		Vector128<ulong> highUpper = Vector128.WidenUpper(eight) + carryLowUpper + carryHighUpper;
		limbs = Vector128.Narrow(low & mask, lowUpper & mask);
		Unsafe.Add(ref limbs, 1) += Vector128.Narrow(low >> Bits, lowUpper >> Bits);
		Unsafe.Add(ref limbs, 8) = Vector128.Narrow(high & mask, highUpper & mask);
		Unsafe.Add(ref limbs, 9) += Vector128.Narrow(high >> Bits, highUpper >> Bits);
	}

	// The columns of lane D of the products times u, by umlal of lane D of each limb with the factors of two columns at a time, column k in lane k & 1 of c_(k/2).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyLaneD(ref Vector128<uint> products, ref Vector128<uint> multiplier, ref Vector128<uint> result)
	{
		Vector128<ulong> c0 = Vector128<ulong>.Zero, c1 = Vector128<ulong>.Zero, c2 = Vector128<ulong>.Zero, c3 = Vector128<ulong>.Zero;
		Vector128<ulong> c4 = Vector128<ulong>.Zero, c5 = Vector128<ulong>.Zero, c6 = Vector128<ulong>.Zero, c7 = Vector128<ulong>.Zero;

		ref Vector64<uint> factors = ref Halves(ref multiplier);

		for (nint i = 0; i < 16; ++i)
		{
			Vector128<uint> limb = Unsafe.Add(ref products, i);
			c0 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c0, factors, limb, 3);
			c1 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c1, Unsafe.Add(ref factors, 1), limb, 3);
			c2 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c2, Unsafe.Add(ref factors, 32), limb, 3);
			c3 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c3, Unsafe.Add(ref factors, 33), limb, 3);
			c4 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c4, Unsafe.Add(ref factors, 64), limb, 3);
			c5 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c5, Unsafe.Add(ref factors, 65), limb, 3);
			c6 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c6, Unsafe.Add(ref factors, 96), limb, 3);
			c7 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(c7, Unsafe.Add(ref factors, 97), limb, 3);
			factors = ref Unsafe.Add(ref factors, 2);
		}

		// Two rounds of carries in that form, then column k, below 2^28 + 2^7 and column 8 below 2^28 + 2^8, goes into lane D of limb k.
		CarryColumns(ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		CarryColumns(ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		InsertLaneD(ref products, ref result, 0, Vector128.Narrow(c0, c1));
		InsertLaneD(ref products, ref result, 4, Vector128.Narrow(c2, c3));
		InsertLaneD(ref products, ref result, 8, Vector128.Narrow(c4, c5));
		InsertLaneD(ref products, ref result, 12, Vector128.Narrow(c6, c7));
	}

	// One carry from each of the columns 0 to 15, two to a vector, into the next, the one out of column 15 into columns 0 and 8.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryColumns(ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> c2, ref Vector128<ulong> c3, ref Vector128<ulong> c4, ref Vector128<ulong> c5, ref Vector128<ulong> c6, ref Vector128<ulong> c7)
	{
		Vector128<ulong> mask = Vector128.Create((ulong)Mask);
		Vector128<ulong> carry0 = c0 >> Bits;
		Vector128<ulong> carry1 = c1 >> Bits;
		Vector128<ulong> carry2 = c2 >> Bits;
		Vector128<ulong> carry3 = c3 >> Bits;
		Vector128<ulong> carry4 = c4 >> Bits;
		Vector128<ulong> carry5 = c5 >> Bits;
		Vector128<ulong> carry6 = c6 >> Bits;
		Vector128<ulong> carry7 = c7 >> Bits;
		c0 = (c0 & mask) + AdvSimd.ExtractVector128(carry7, carry0, 1);
		c1 = (c1 & mask) + AdvSimd.ExtractVector128(carry0, carry1, 1);
		c2 = (c2 & mask) + AdvSimd.ExtractVector128(carry1, carry2, 1);
		c3 = (c3 & mask) + AdvSimd.ExtractVector128(carry2, carry3, 1);
		c4 = (c4 & mask) + AdvSimd.ExtractVector128(carry3, carry4, 1) + AdvSimd.ExtractVector128(carry7, Vector128<ulong>.Zero, 1);
		c5 = (c5 & mask) + AdvSimd.ExtractVector128(carry4, carry5, 1);
		c6 = (c6 & mask) + AdvSimd.ExtractVector128(carry5, carry6, 1);
		c7 = (c7 & mask) + AdvSimd.ExtractVector128(carry6, carry7, 1);
	}

	// Lane D of limbs first to first + 3 from the lanes of columns, the others as the products leave them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InsertLaneD(ref Vector128<uint> products, ref Vector128<uint> result, nint first, Vector128<uint> columns)
	{
		Unsafe.Add(ref result, first) = AdvSimd.Arm64.InsertSelectedScalar(Unsafe.Add(ref products, first), 3, columns, 0);
		Unsafe.Add(ref result, first + 1) = AdvSimd.Arm64.InsertSelectedScalar(Unsafe.Add(ref products, first + 1), 3, columns, 1);
		Unsafe.Add(ref result, first + 2) = AdvSimd.Arm64.InsertSelectedScalar(Unsafe.Add(ref products, first + 2), 3, columns, 2);
		Unsafe.Add(ref result, first + 3) = AdvSimd.Arm64.InsertSelectedScalar(Unsafe.Add(ref products, first + 3), 3, columns, 3);
	}

	// Sixteen limbs of two lanes in 64-bit lanes.
	[InlineArray(16)]
	private struct Wide
	{
		private Vector128<ulong> _element0;
	}
}
