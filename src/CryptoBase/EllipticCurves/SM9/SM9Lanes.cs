namespace CryptoBase.EllipticCurves.SM9;

// An element of Fp12 for the vector kernels, as Fp12 = Fp2[W]/(W⁶ − u) with W = w: the Fp2 coefficient of W^k, the coefficient of w^k in SM9Fp12, in lane k of rows of eight 64-bit lanes, its real part in rows 0 to 9 and its u-part in rows 10 to 19, row l holding limb l of radix 2^26 with the Montgomery form of SM9Fp. Lanes 6 and 7 are padding, which the operations fill with values of no meaning. A coefficient is reduced if limbs 0 to 8 are below 2^26 and its value is below 2.25p, as for SM9Fp, so the five limbs of an SM9Fp are the pairs of these.
[InlineArray(Length)]
internal struct SM9Fp12Lanes
{
	internal const int Length = 160;

	private ulong _element0;
}

// The working memory of SM9Lanes, which the operations overwrite: its regions end with the rows of the line of the doubling step, at LineRows + 2·ComponentLength = 1984. It holds secrets, so its owner erases it.
[InlineArray(Length)]
internal struct SM9LaneScratch
{
	internal const int Length = 1984;

	private ulong _element0;
}

// The arithmetic of Fp12 on SM9Fp12Lanes, which every vector kernel shares over its lanes. A product of two elements is the cyclic convolution c_k = Σ_i a_i·b'_(k−i) over the lanes, b'_j = b_j for j ≥ 0 and u·b_(j+6) otherwise, as W⁶ = u: term i broadcasts a_i to every lane and takes b rotated by i lanes, whose rows SM9Lanes reads at a shifted offset from an extended copy, so that no product needs a shuffle. Each lane takes the product of Fp2 by Karatsuba, P0 = x0·y0, P1 = x1·y1 and Ps = (x0 + x1)(y0 + y1), summed over the terms as 19 columns before one Montgomery reduction per coefficient.
// Every member takes and gives reduced coefficients, except the line of DoublingStep, whose l0 MultiplyByLine takes as it is, and erases nothing: the callers own the elements and the scratch. None branches on or indexes by a value. Any result may be the same element as an input.
internal static partial class SM9Lanes<TVector> where TVector : unmanaged, ISM9Vector<TVector>
{
	internal const int RowLength = 8;

	private const int Lanes = 6;

	private const int LimbCount = 10;

	private const int ComponentLength = LimbCount * RowLength;

	private const int ExtendedRowLength = 16;

	// An extended row for each limb, then one for each sum of limbs m and m + 5, the halves of Karatsuba.
	private const int HalfLimbs = LimbCount / 2;

	private const int ExtendedLength = (LimbCount + HalfLimbs) * ExtendedRowLength;

	private const int WideRows = 20;

	private const int WideLength = WideRows * RowLength;

	// The regions of the scratch: three sets of products, the extended rows of the right operand or the six rows of the operands of a lane product, and the left sums or a reduced temporary.
	private const int Products = 0;

	private const int Extended = Products + 3 * WideLength;

	private const int Operands = Extended;

	private const int LeftSums = Extended + 3 * ExtendedLength;

	private const int Temporary = LeftSums + ComponentLength;

	private const int Combined = Temporary + 2 * ComponentLength;

	private const int Permuted = Combined + 2 * WideLength;

	private const int LineRows = Permuted + 8 * RowLength;

	private const ulong Mask = (1UL << 26) - 1;

	// −p⁻¹ mod 2^26.
	private const uint NegativeInverse = 0x32EE42B;

	// ⌊2^40/(P9 + 1)⌋ for the quotient of WeakReduce.
	private const uint QuotientMultiplier = 0x59E60;

	// The limbs of p in radix 2^26.
	private const uint P0 = 0x351457D;
	private const uint P1 = 0x3E6C9F8;
	private const uint P2 = 0x2EDBE56;
	private const uint P3 = 0x12C69EB;
	private const uint P4 = 0x121F293;
	private const uint P5 = 0x163B1D1;
	private const uint P6 = 0x03AB4FF;
	private const uint P7 = 0x29BC758;
	private const uint P8 = 0x00002A3;
	private const uint P9 = 0x2D9000;

	// The lanes of each source, four bits each from lane 0: rotation by three lanes, and the two permutations of the cyclotomic square, whose sources are the real and the u-part of a set of products.
	private const ulong RotateThree = 0x76210543;
	private const ulong PermuteReal = 0x761504A3;
	private const ulong PermuteImaginary = 0xFE9D8C2B;
	private const ulong SpreadEven = 0x76221100;

	// The patterns of the doubling step: (X, Y, Z, X, Y) and (Y, Y, Z, X, Z) for the first products, the latter with the other part of Z for u·Z; (A, B, B, E, 3X², 2YZ), E everywhere and (B, B, 2YZ, E) for the second; lane 3 into lane 1; and the line from lane 0 of the first row and lanes 4 and 5 of the second.
	private const ulong DoublingLeft = 0x76510210;
	private const ulong DoublingRight = 0x76520A11;
	private const ulong SecondLeft = 0x76432110;
	private const ulong SpreadE = 0x76222222;
	private const ulong SecondRight = 0x76542411;
	private const ulong LaneThreeToOne = 0x76543230;
	private const ulong AssembleLinePattern = 0x7654DC10;

	// The patterns of the square: the pairs of lanes swapped, the odd lanes (u·a5, a1, a3) from both rows, the even lanes into the odd ones and back, and (v·t) on the even lanes, lane 0 from lane 4 of the other row.
	private const ulong SwapPairs = 0x76452301;
	private const ulong SquareSum = 0x763412D0;
	private const ulong EvenToOdd = 0x76442200;
	private const ulong OddToEven = 0x76553311;
	private const ulong TimesV = 0x7652301C;

	// Every lane two up, for the extended rows.
	private const ulong TwoLanesUp = 0x54321010;

	// The qword of b'_0 in an extended row, which Extend lays out.
	private static int ExtendedOrigin
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TVector.Count == RowLength ? RowLength : Lanes;
	}

	private static int VectorCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => (Lanes + TVector.Count - 1) / TVector.Count;
	}

	// 3p in limbs that cover those of a reduced element, limbs 0 to 8 in [2^26, 2^27) and limb 9 above that of 2.25p, so that 3p − x has no negative limb for a reduced x.
	private static ReadOnlySpan<ulong> ThreeP => [0x5F3D077, 0x7B45DE9, 0x4C93B03, 0x7853DC2, 0x765D7B8, 0x42B1572, 0x4B01EFD, 0x7D35607, 0x40007E9, 0x88AFFF];

	// 64p² in twenty canonical columns.
	private static ReadOnlySpan<ulong> Offset => [0x1A7C240, 0x51EB9F, 0x956C9F, 0xF0B52A, 0x340FB7E, 0x2C32C3F, 0x2107AAC, 0x23524A1, 0x213EFC4, 0x122D09C, 0x137C7FB, 0x2117337, 0x200F40E, 0x1FEC144, 0x2F9F4CC, 0x14EE814, 0x3CC2949, 0x333553, 0xF08, 0x81BF10];

	// Lane masks of a row: lanes 3 to 5, the even lanes, the odd lanes and lane 1.
	private static ReadOnlySpan<ulong> HighLanes => [0, 0, 0, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 0, 0];

	private static ReadOnlySpan<ulong> EvenLanes => [ulong.MaxValue, 0, ulong.MaxValue, 0, ulong.MaxValue, 0, 0, 0];

	private static ReadOnlySpan<ulong> OddLanes => [0, ulong.MaxValue, 0, ulong.MaxValue, 0, ulong.MaxValue, 0, 0];

	private static ReadOnlySpan<ulong> LaneOne => [0, ulong.MaxValue, 0, 0, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> LaneZero => [ulong.MaxValue, 0, 0, 0, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> LaneTwo => [0, 0, ulong.MaxValue, 0, 0, 0, 0, 0];

	private static ReadOnlySpan<ulong> FactorLanes => [0, 0, 0, 0, ulong.MaxValue, ulong.MaxValue, 0, 0];

	private static ReadOnlySpan<ulong> LineLanes => [ulong.MaxValue, 0, ulong.MaxValue, ulong.MaxValue, 0, 0, 0, 0];

	// The lane factors of the doubling step: 3Z, then 3X and 2Z, of the first products, 5 for E = 5·3uC, and 2A and 4B of the second products.
	private static ReadOnlySpan<ulong> DoublingLeftScale => [1, 1, 3, 1, 1, 1, 1, 1];

	private static ReadOnlySpan<ulong> DoublingRightScale => [1, 1, 1, 3, 2, 1, 1, 1];

	private static ReadOnlySpan<ulong> LevelScale => [1, 1, 5, 1, 1, 1, 1, 1];

	private static ReadOnlySpan<ulong> SecondLeftScale => [2, 1, 4, 1, 1, 1, 1, 1];

	// 9p in limbs that cover three times those of a reduced element, limbs 0 to 8 in [3·2^26 − 3, 2^28), so that 9p − 3x has no negative limb.
	private static ReadOnlySpan<ulong> NineP => [0xDDB7165, 0xF1D19BC, 0xE5BB10B, 0xE8FB946, 0xE31872A, 0xC814058, 0xE105CF7, 0xF7A0215, 0xC0017BD, 0x19A0FFD];

	// The factors of the Frobenius maps in Montgomery form, lane k holding w^(k(q − 1)) for q = p, p² and p³ in ten rows, with the −1 of the conjugations of p² and p³ folded in.
	private static ReadOnlySpan<ulong> Frobenius1 =>
	[
		0x3040742, 0x321297, 0x1D0E1A6, 0x351CB37, 0x2CCDA64, 0x270FE1D, 0x0, 0x0,
		0x22AA49D, 0xC6B373, 0x986347, 0x103FB58, 0x26DBEA9, 0x2411DE, 0x0, 0x0,
		0x391A486, 0x2EA702E, 0x3AB3978, 0x16F8F4A, 0x1994F1, 0x172DD73, 0x0, 0x0,
		0x22EE5BD, 0x387B61C, 0x2FD2768, 0x200B511, 0xCE41AB, 0x3A568E0, 0x0, 0x0,
		0x3152757, 0x33333CC, 0x23EB18C, 0x2F6F244, 0x3298A35, 0xE5B10A, 0x0, 0x0,
		0x16EB803, 0x16E0A11, 0x37DE105, 0xA23FEE, 0x20F2901, 0x97E7AE, 0x0, 0x0,
		0x2F4720E, 0x637B1C, 0x3E848FE, 0x24F7F5D, 0xF3D6F0, 0x226B940, 0x0, 0x0,
		0x29CDE6E, 0x2FBDDCF, 0x12D186B, 0xC44E9C, 0x29039FD, 0x643825, 0x0, 0x0,
		0x3FFC5EF, 0x15D37C6, 0x3485AD5, 0x25273D, 0x34894E5, 0x2C7F21A, 0x0, 0x0,
		0x159FFF, 0x2B8D00, 0x16B4F9, 0x10D3BB, 0x114F9, 0x12D6BA, 0x0, 0x0,
	];

	private static ReadOnlySpan<ulong> Frobenius2 =>
	[
		0x3040742, 0x1D0E1A6, 0x2CCDA64, 0x4D3E3B, 0x18063D7, 0x846B19, 0x0, 0x0,
		0x22AA49D, 0x986347, 0x26DBEA9, 0x1BC255B, 0x34E66B1, 0x1790B4F, 0x0, 0x0,
		0x391A486, 0x3AB3978, 0x1994F1, 0x35C19D0, 0x34284DE, 0x2D42965, 0x0, 0x0,
		0x22EE5BD, 0x2FD2768, 0xCE41AB, 0x2FD842D, 0x22F4282, 0x5E2840, 0x0, 0x0,
		0x3152757, 0x23EB18C, 0x3298A35, 0x20CCB3B, 0x2E34106, 0x1F8685E, 0x0, 0x0,
		0x16EB803, 0x37DE105, 0x20F2901, 0x3F4F9CD, 0x1E5D0CB, 0x35488CF, 0x0, 0x0,
		0x2F4720E, 0x3E848FE, 0xF3D6F0, 0x14642F0, 0x526C00, 0x346DE0E, 0x0, 0x0,
		0x29CDE6E, 0x12D186B, 0x29039FD, 0x3FEE8E9, 0x16EAEEC, 0xB8D5A, 0x0, 0x0,
		0x3FFC5EF, 0x3485AD5, 0x34894E5, 0x3CB3, 0xB7A7CE, 0xB76DBE, 0x0, 0x0,
		0x159FFF, 0x16B4F9, 0x114F9, 0x17F000, 0x16DB06, 0x2C7B06, 0x0, 0x0,
	];

	private static ReadOnlySpan<ulong> Frobenius3 =>
	[
		0x3040742, 0x351CB37, 0x4D3E3B, 0x3FF7A46, 0x3040742, 0x351CB37, 0x0, 0x0,
		0x22AA49D, 0x103FB58, 0x1BC255B, 0x2E2CE9F, 0x22AA49D, 0x103FB58, 0x0, 0x0,
		0x391A486, 0x16F8F4A, 0x35C19D0, 0x17E2F0C, 0x391A486, 0x16F8F4A, 0x0, 0x0,
		0x22EE5BD, 0x200B511, 0x2FD842D, 0x32BB4DA, 0x22EE5BD, 0x200B511, 0x0, 0x0,
		0x3152757, 0x2F6F244, 0x20CCB3B, 0x22B004E, 0x3152757, 0x2F6F244, 0x0, 0x0,
		0x16EB803, 0xA23FEE, 0x3F4F9CD, 0xC171E2, 0x16EB803, 0xA23FEE, 0x0, 0x0,
		0x2F4720E, 0x24F7F5D, 0x14642F0, 0x1EB35A2, 0x2F4720E, 0x24F7F5D, 0x0, 0x0,
		0x29CDE6E, 0xC44E9C, 0x3FEE8E9, 0x1D778BB, 0x29CDE6E, 0xC44E9C, 0x0, 0x0,
		0x3FFC5EF, 0x25273D, 0x3CB3, 0x3DADB66, 0x3FFC5EF, 0x25273D, 0x0, 0x0,
		0x159FFF, 0x10D3BB, 0x17F000, 0x1CBC44, 0x159FFF, 0x10D3BB, 0x0, 0x0,
	];

	// The element of value, whose coefficients must be reduced.
	internal static void FromFp12(in SM9Fp12 value, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		Split(in value.C0.C0, ref rows, 0);
		Split(in value.C1.C0, ref rows, 1);
		Split(in value.C0.C1, ref rows, 2);
		Split(in value.C1.C1, ref rows, 3);
		Split(in value.C0.C2, ref rows, 4);
		Split(in value.C1.C2, ref rows, 5);
	}

	internal static void ToFp12(ref readonly SM9Fp12Lanes value, out SM9Fp12 result)
	{
		ref ulong rows = ref Unsafe.AsRef(in value[0]);
		Unsafe.SkipInit(out result);
		Join(ref rows, 0, out result.C0.C0);
		Join(ref rows, 1, out result.C1.C0);
		Join(ref rows, 2, out result.C0.C1);
		Join(ref rows, 3, out result.C1.C1);
		Join(ref rows, 4, out result.C0.C2);
		Join(ref rows, 5, out result.C1.C2);
	}

	// The line l0 + l2·w² + l3·w³, in lanes 0, 2 and 3; the other lanes are 0.
	internal static void FromLine(in SM9Fp2 l0, in SM9Fp2 l2, in SM9Fp2 l3, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref rows), 0, SM9Fp12Lanes.Length * sizeof(ulong));
		Split(in l0, ref rows, 0);
		Split(in l2, ref rows, 2);
		Split(in l3, ref rows, 3);
	}

	private static void Split(in SM9Fp2 value, ref ulong rows, int lane)
	{
		Split(in value.A0, ref Unsafe.Add(ref rows, lane));
		Split(in value.A1, ref Unsafe.Add(ref rows, ComponentLength + lane));
	}

	// ReSharper disable once RedundantAssignment
	private static void Split(in SM9Fp value, ref ulong rows)
	{
		rows = value.L0 & Mask;
		Unsafe.Add(ref rows, 8) = value.L0 >> 26;
		Unsafe.Add(ref rows, 16) = value.L1 & Mask;
		Unsafe.Add(ref rows, 24) = value.L1 >> 26;
		Unsafe.Add(ref rows, 32) = value.L2 & Mask;
		Unsafe.Add(ref rows, 40) = value.L2 >> 26;
		Unsafe.Add(ref rows, 48) = value.L3 & Mask;
		Unsafe.Add(ref rows, 56) = value.L3 >> 26;
		Unsafe.Add(ref rows, 64) = value.L4 & Mask;
		Unsafe.Add(ref rows, 72) = value.L4 >> 26;
	}

	private static void Join(ref ulong rows, int lane, out SM9Fp2 result)
	{
		Unsafe.SkipInit(out result);
		Join(ref Unsafe.Add(ref rows, lane), out result.A0);
		Join(ref Unsafe.Add(ref rows, ComponentLength + lane), out result.A1);
	}

	private static void Join(ref ulong rows, out SM9Fp result)
	{
		result.L0 = rows | Unsafe.Add(ref rows, 8) << 26;
		result.L1 = Unsafe.Add(ref rows, 16) | Unsafe.Add(ref rows, 24) << 26;
		result.L2 = Unsafe.Add(ref rows, 32) | Unsafe.Add(ref rows, 40) << 26;
		result.L3 = Unsafe.Add(ref rows, 48) | Unsafe.Add(ref rows, 56) << 26;
		result.L4 = Unsafe.Add(ref rows, 64) | Unsafe.Add(ref rows, 72) << 26;
	}

	// The terms of a product, the lanes of the left operand, four bits each: every lane, or the lanes 0, 2 and 3 of a line. Each term broadcasts its coefficient from the qword of left that its source gives, SourceBits each, the lane itself here.
	private const ulong AllTerms = 0x543210;

	private const ulong AllSources = 1UL << SourceBits | 2UL << 2 * SourceBits | 3UL << 3 * SourceBits | 4UL << 4 * SourceBits | 5UL << 5 * SourceBits;

	private const ulong LineTerms = 0x320;

	private const ulong LineSources = 2UL << SourceBits | 3UL << 2 * SourceBits;

	// The terms of a line of EvaluateLines, l0 and l2, at the lanes 0 and 2 of the product.
	private const ulong NormalizedLineTerms = 0x20;

	// The terms of a factor of Fp6, the even lanes.
	private const ulong EvenTerms = 0x420;

	private const ulong EvenSources = 2UL << SourceBits | 4UL << 2 * SourceBits;

	// The terms of a product of two lines of EvaluateLinePairs, its coefficients at the lanes 0, 2, 3, 4 and 5 of the product, and their sources in a batch of pairs for the pair of lane 0, to each of which PairLaneSources times the lane of the pair adds the lane.
	private const ulong PairTerms = 0x54320;

	private const ulong PairSources = (ulong)PairCoefficientLength << SourceBits | 2UL * PairCoefficientLength << 2 * SourceBits | 3UL * PairCoefficientLength << 3 * SourceBits | 4UL * PairCoefficientLength << 4 * SourceBits;

	private const ulong PairLaneSources = 1 | 1UL << SourceBits | 1UL << 2 * SourceBits | 1UL << 3 * SourceBits | 1UL << 4 * SourceBits;

	// The bits of a source, which reaches the last coefficient of a batch of pairs: 4·PairCoefficientLength + 7 = 967 at most.
	private const int SourceBits = 10;

	internal static void Multiply(ref SM9Fp12Lanes left, ref SM9Fp12Lanes right, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Product(ref left[0], ref right[0], AllTerms, AllSources, 6, ref result[0], ref scratch[0]);
	}

	// factor·value for a factor of Fp6, its coefficients in the even lanes and 0 in the odd ones: the three terms of the even lanes, with the bounds of Multiply over three terms rather than six.
	internal static void MultiplyByFp6(ref SM9Fp12Lanes factor, ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Product(ref factor[0], ref value[0], EvenTerms, EvenSources, 3, ref result[0], ref scratch[0]);
	}

	// value·l for a line l = l0 + l2·w² + l3·w³ in lanes 0, 2 and 3, the terms of Product. A reduced line, from FromLine, has the bounds of Multiply over three terms rather than six. From DoublingStep, l0 is below 4.0001p with limbs below 2^27.6 and l2 and l3 below 1.0001p: c0 = x0·y0 − 2x1·y1 then lies in (−27p², 36p²) and c1 in [0, 50p²), and the columns of Ps, whose left sums for l0 are below 2^28.6, stay below 2^61.
	internal static void MultiplyByLine(ref SM9Fp12Lanes value, ref SM9Fp12Lanes line, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Product(ref line[0], ref value[0], LineTerms, LineSources, 3, ref result[0], ref scratch[0]);
	}

	// value·(l0 + l2·w² + w³) for line j of a batch of EvaluateLines, l0 and l2 reduced: the terms of l0 and l2, at the lanes 0 and 2 of a line, from lane j of the batch rows, and value·w³, value rotated by three lanes as the extended rows hold it for lane 3, which ReduceProducts adds to c0 and c1 times R, so that its reduction adds it to the result. The two terms have the bounds of Multiply over two terms rather than six, so c0 lies in (−20.3p², 27p²) and c1 in [0, 37.2p²), and the rotated value has components below 6p and 2.25p, which add below 134.8p² and 50.6p²: c0 + 64p² and c1 are below 226p², which Reduce2 takes, and the columns stay below 2^61.4 in magnitude.
	internal static void MultiplyByNormalizedLine(ref SM9Fp12Lanes value, ref ulong batch, int line, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Debug.Assert(line < BatchLines);

		ref ulong work = ref scratch[0];
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong extended = ref Unsafe.Add(ref work, Extended);
		ulong sources = (ulong)(ComponentLength + line) << SourceBits | (uint)line;
		Extend(ref value[0], ref extended, LineHalves);

		for (int v = 0; v < VectorCount; ++v)
		{
			AccumulateLine(ref batch, ref extended, sources, v, ref products);
			AccumulateLine(ref Unsafe.Add(ref batch, BatchComponentLength), ref Unsafe.Add(ref extended, ExtendedLength), sources, v, ref Unsafe.Add(ref products, WideLength));
			AccumulateLine(ref Unsafe.Add(ref batch, 2 * BatchComponentLength), ref Unsafe.Add(ref extended, 2 * ExtendedLength), sources, v, ref Unsafe.Add(ref products, 2 * WideLength));
		}

		ref ulong unit = ref Unsafe.Add(ref extended, ExtendedOrigin - 3);

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref products, true, ref unit, v, ref result[0]);
		}
	}

	// The lines of a batch, one in each lane of the vectors that hold a row: BatchLines of them, or the last ones.
	internal static int BatchLines
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => VectorCount * TVector.Count;
	}

	// The ulongs of a batch of lines and of the factors that EvaluateLines takes: for each component of Karatsuba, the real parts, the u-parts and their sums, the rows of l0 and then those of l2, and the rows of α and of β.
	internal const int LineBatchLength = 3 * BatchComponentLength + 2 * ComponentLength;

	private const int BatchComponentLength = 2 * ComponentLength;

	private const int BatchFactors = 3 * BatchComponentLength;

	// α and β of SM9MillerLoop.FactorsVariableTime in every lane of the rows of the factors of a batch.
	internal static void SplitFactors(in SM9Fp alpha, in SM9Fp beta, ref ulong batch)
	{
		ref ulong factors = ref Unsafe.Add(ref batch, BatchFactors);

		for (int lane = 0; lane < RowLength; ++lane)
		{
			Split(in alpha, ref Unsafe.Add(ref factors, lane));
			Split(in beta, ref Unsafe.Add(ref factors, ComponentLength + lane));
		}
	}

	// l0 = A·α and l2 = B·β of the lines, at most BatchLines of them, line j in lane j of the batch, as SM9MillerLoop.Evaluate gives them, by the lane products of Fp of Scale: the components of A and B go into lanes, each takes its factor, and Reduce2 takes the real and the u-part of each side by side, from products below 5.07p² to below 1.0001p in limbs below 2^26; the sums of the real and the u-parts follow, below 2.0002p in limbs below 2^27. Lanes past the lines hold values of no meaning.
	internal static void EvaluateLines(ReadOnlySpan<SM9PrecomputedLine> lines, ref ulong batch, ref SM9LaneScratch scratch)
	{
		Debug.Assert(lines.Length <= BatchLines);

		ref ulong real = ref batch;
		ref ulong imaginary = ref Unsafe.Add(ref batch, BatchComponentLength);
		ref ulong sums = ref Unsafe.Add(ref batch, 2 * BatchComponentLength);
		ref ulong alpha = ref Unsafe.Add(ref batch, BatchFactors);
		ref ulong beta = ref Unsafe.Add(ref alpha, ComponentLength);
		ref ulong products = ref Unsafe.Add(ref scratch[0], Products);
		ref ulong other = ref Unsafe.Add(ref products, WideLength);

		for (int j = 0; j < lines.Length; ++j)
		{
			Split(in lines[j].A.A0, ref Unsafe.Add(ref real, j));
			Split(in lines[j].B.A0, ref Unsafe.Add(ref real, ComponentLength + j));
			Split(in lines[j].A.A1, ref Unsafe.Add(ref imaginary, j));
			Split(in lines[j].B.A1, ref Unsafe.Add(ref imaginary, ComponentLength + j));
		}

		Evaluate(ref real, ref imaginary, ref alpha, ref products, ref other);
		Evaluate(ref Unsafe.Add(ref real, ComponentLength), ref Unsafe.Add(ref imaginary, ComponentLength), ref beta, ref products, ref other);
		AddRows(ref real, ref imaginary, ref sums);
		AddRows(ref Unsafe.Add(ref real, ComponentLength), ref Unsafe.Add(ref imaginary, ComponentLength), ref Unsafe.Add(ref sums, ComponentLength));
	}

	// The real and the u-part of a coefficient of the lines times the rows of its factor, in place.
	private static void Evaluate(ref ulong real, ref ulong imaginary, ref ulong factor, ref ulong products, ref ulong other)
	{
		for (int v = 0; v < VectorCount; ++v)
		{
			AccumulateLanes(ref real, ref factor, v, ref products);
			AccumulateLanes(ref imaginary, ref factor, v, ref other);
		}

		ClearTopColumns(ref products);
		ClearTopColumns(ref other);

		for (int v = 0; v < VectorCount; ++v)
		{
			Reduce2(ref Unsafe.Add(ref products, v * TVector.Count), ref Unsafe.Add(ref other, v * TVector.Count), ref Unsafe.Add(ref real, v * TVector.Count), ref Unsafe.Add(ref imaginary, v * TVector.Count));
		}
	}

	// The qword of left from which term t of sources broadcasts.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int Source(ulong sources, int t)
	{
		return (int)(sources >> SourceBits * t) & (1 << SourceBits) - 1;
	}

	// The ulongs of a batch of pairs of EvaluateLinePairs: for each coefficient c0, c2, c3, c4 and c5 of the products, the rows of its real parts, its u-parts and their sums.
	internal const int PairBatchLength = PairCoefficients * PairCoefficientLength;

	private const int PairCoefficients = 5;

	private const int PairCoefficientLength = 3 * ComponentLength;

	// The limbs of the Montgomery form of 1.
	private static ReadOnlySpan<ulong> MontgomeryOne => [0x3040742, 0x22AA49D, 0x391A486, 0x22EE5BD, 0x3152757, 0x16EB803, 0x2F4720E, 0x29CDE6E, 0x3FFC5EF, 0x159FFF];

	// The products L = l·l′ of line j of batch and line j of otherBatch, two batches of EvaluateLines, into lane j of pairs. As w⁶ = u, (l0 + l2·w² + w³)(l0′ + l2′·w² + w³) = (l0·l0′ + u) + (l0·l2′ + l2·l0′)·w² + (l0 + l0′)·w³ + l2·l2′·w⁴ + (l2 + l2′)·w⁵. The three products of Fp2 take the lane products of Fp, by Karatsuba each, and l0·l2′ + l2·l0′ the columns of (l0 + l2)(l0′ + l2′) less those of l0·l0′ and l2·l2′, before one reduction: the lines are below 1.0001p in limbs below 2^26 and their sums below 2.0002p in limbs below 2^27, so each column of the three products stays below 2^60, and the values of the reductions, the real parts below 64p² + 2.0004p² and the u-parts below 4.0008p², stay within what Reduce2 takes. The coefficients that take an addition, the u-part of l0·l0′ + u, l0 + l0′ and l2 + l2′, are weakly reduced, so all of them end below 1.0001p in limbs below 2^26, and their sums below 2.0002p in limbs below 2^27, as those of a reduced line. Lanes past the lines of the batches hold values of no meaning.
	internal static void EvaluateLinePairs(ref ulong batch, ref ulong otherBatch, ref ulong pairs, ref SM9LaneScratch scratch)
	{
		ref ulong work = ref scratch[0];
		// The products of Fp2 as three sets of columns each, and the sums of the lines of each batch.
		ref ulong first = ref work;
		ref ulong second = ref Unsafe.Add(ref first, 3 * WideLength);
		ref ulong cross = ref Unsafe.Add(ref second, 3 * WideLength);
		ref ulong sums = ref Unsafe.Add(ref cross, 3 * WideLength);
		ref ulong otherSums = ref Unsafe.Add(ref sums, 3 * ComponentLength);

		for (int c = 0; c < 3; ++c)
		{
			ref ulong component = ref Unsafe.Add(ref batch, BatchComponentLength * c);
			ref ulong otherComponent = ref Unsafe.Add(ref otherBatch, BatchComponentLength * c);
			AddRows(ref component, ref Unsafe.Add(ref component, ComponentLength), ref Unsafe.Add(ref sums, ComponentLength * c));
			AddRows(ref otherComponent, ref Unsafe.Add(ref otherComponent, ComponentLength), ref Unsafe.Add(ref otherSums, ComponentLength * c));
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			for (int c = 0; c < 3; ++c)
			{
				ref ulong component = ref Unsafe.Add(ref batch, BatchComponentLength * c);
				ref ulong otherComponent = ref Unsafe.Add(ref otherBatch, BatchComponentLength * c);
				AccumulateLanes(ref component, ref otherComponent, v, ref Unsafe.Add(ref first, WideLength * c));
				AccumulateLanes(ref Unsafe.Add(ref component, ComponentLength), ref Unsafe.Add(ref otherComponent, ComponentLength), v, ref Unsafe.Add(ref second, WideLength * c));
				AccumulateLanes(ref Unsafe.Add(ref sums, ComponentLength * c), ref Unsafe.Add(ref otherSums, ComponentLength * c), v, ref Unsafe.Add(ref cross, WideLength * c));
			}
		}

		SubtractColumns(ref cross, ref first, ref second);

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref first, v, ref pairs);
			ReduceProducts(ref cross, v, ref Unsafe.Add(ref pairs, PairCoefficientLength));
			ReduceProducts(ref second, v, ref Unsafe.Add(ref pairs, 3 * PairCoefficientLength));
		}

		ref ulong c0 = ref Unsafe.Add(ref pairs, ComponentLength);
		ReadOnlySpan<ulong> one = MontgomeryOne;

		for (int m = 0; m < LimbCount; ++m)
		{
			for (int i = 0; i < RowLength; i += TVector.Count)
			{
				ref ulong row = ref Unsafe.Add(ref c0, RowLength * m + i);
				(TVector.Load(in row) + TVector.Create(one[m])).Store(ref row);
			}
		}

		WeakReduceRows(ref c0);

		for (int c = 0; c < 2; ++c)
		{
			ref ulong target = ref Unsafe.Add(ref pairs, (2 + 2 * c) * PairCoefficientLength);
			AddRows(ref Unsafe.Add(ref batch, ComponentLength * c), ref Unsafe.Add(ref otherBatch, ComponentLength * c), ref target);
			AddRows(ref Unsafe.Add(ref batch, BatchComponentLength + ComponentLength * c), ref Unsafe.Add(ref otherBatch, BatchComponentLength + ComponentLength * c), ref Unsafe.Add(ref target, ComponentLength));
			WeakReduceRows(ref target);
			WeakReduceRows(ref Unsafe.Add(ref target, ComponentLength));
		}

		for (int c = 0; c < PairCoefficients; ++c)
		{
			ref ulong coefficient = ref Unsafe.Add(ref pairs, PairCoefficientLength * c);
			AddRows(ref coefficient, ref Unsafe.Add(ref coefficient, ComponentLength), ref Unsafe.Add(ref coefficient, 2 * ComponentLength));
		}
	}

	// The three sets of the columns of a product of Fp2 at cross less those at first and at second, in place, rows 0 to 18 of each, which the lane products write.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void SubtractColumns(ref ulong cross, ref ulong first, ref ulong second)
	{
		for (int i = 0; i < 3 * WideLength; i += WideLength)
		{
			for (int j = 0; j < (WideRows - 1) * RowLength; j += TVector.Count)
			{
				ref ulong target = ref Unsafe.Add(ref cross, i + j);
				(TVector.Load(in target) - TVector.Load(in Unsafe.Add(ref first, i + j)) - TVector.Load(in Unsafe.Add(ref second, i + j))).Store(ref target);
			}
		}
	}

	// value·L for the product L of line j of a batch of pairs of EvaluateLinePairs, by the five terms of its coefficients from lane j of their rows. They are below 1.0001p in limbs below 2^26, as reduced coefficients are, so the terms have the bounds of Multiply over five terms rather than six.
	internal static void MultiplyByLinePair(ref SM9Fp12Lanes value, ref ulong pairs, int line, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Debug.Assert(line < BatchLines);

		ref ulong work = ref scratch[0];
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong extended = ref Unsafe.Add(ref work, Extended);
		ref ulong middle = ref Unsafe.Add(ref work, Combined);
		ulong sources = PairSources + PairLaneSources * (uint)line;
		Extend(ref value[0], ref extended, true);

		for (int v = 0; v < VectorCount; ++v)
		{
			Accumulate(ref pairs, ref extended, PairTerms, sources, PairCoefficients, v, ref products, ref middle);
			Accumulate(ref Unsafe.Add(ref pairs, ComponentLength), ref Unsafe.Add(ref extended, ExtendedLength), PairTerms, sources, PairCoefficients, v, ref Unsafe.Add(ref products, WideLength), ref middle);
			Accumulate(ref Unsafe.Add(ref pairs, 2 * ComponentLength), ref Unsafe.Add(ref extended, 2 * ExtendedLength), PairTerms, sources, PairCoefficients, v, ref Unsafe.Add(ref products, 2 * WideLength), ref middle);
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref products, v, ref result[0]);
		}
	}

	// The product L of line j of a batch of pairs as an element: its coefficients in lanes 0, 2, 3, 4 and 5 and 0 in lane 1.
	internal static void FromLinePair(ref ulong pairs, int line, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref rows), 0, SM9Fp12Lanes.Length * sizeof(ulong));

		for (int c = 0; c < PairCoefficients; ++c)
		{
			ref ulong coefficient = ref Unsafe.Add(ref pairs, PairCoefficientLength * c + line);
			int lane = c is 0 ? 0 : c + 1;

			for (int m = 0; m < LimbCount; ++m)
			{
				int row = RowLength * m;
				Unsafe.Add(ref rows, row + lane) = Unsafe.Add(ref coefficient, row);
				Unsafe.Add(ref rows, ComponentLength + row + lane) = Unsafe.Add(ref coefficient, ComponentLength + row);
			}
		}
	}

	// The line l0 + l2·w² + w³ of line j of a batch as an element: l0 and l2 in lanes 0 and 2, 1 in lane 3 and 0 elsewhere.
	internal static void FromNormalizedLine(ref ulong batch, int line, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		ref ulong imaginary = ref Unsafe.Add(ref batch, BatchComponentLength);
		Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref rows), 0, SM9Fp12Lanes.Length * sizeof(ulong));

		for (int m = 0; m < LimbCount; ++m)
		{
			int row = RowLength * m;
			Unsafe.Add(ref rows, row) = Unsafe.Add(ref batch, row + line);
			Unsafe.Add(ref rows, row + 2) = Unsafe.Add(ref batch, ComponentLength + row + line);
			Unsafe.Add(ref rows, ComponentLength + row) = Unsafe.Add(ref imaginary, row + line);
			Unsafe.Add(ref rows, ComponentLength + row + 2) = Unsafe.Add(ref imaginary, ComponentLength + row + line);
		}

		Split(in SM9Fp.One, ref Unsafe.Add(ref rows, 3));
	}

	// For reduced inputs, the lanes of the left sums have limbs below 2^27, those of the extended rows below 2^28 and 2^28.33 for the sums, so each column of P0, P1 and Ps over six terms is below 2^59.4, 2^57.8 and 2^60.8, and those of c0 = P0 − 2P1 and c1 = Ps − P0 − P1 below 2^60.1 and 2^61.4 in magnitude. As values, c0 = Σ x0·y0 − 2x1·y1 lies in (−60.75p², 81p²), the wrapped y0 = 2(3p − y1) being below 6p, and c1 = Σ x0·y1 + x1·y0 in [0, 111.4p²), so c0 + 64p² and c1 are below 145p², which Reduce2 takes to below 7.5p and then to below 1.0001p.
	[SkipLocalsInit]
	private static void Product(ref ulong a, ref ulong b, ulong terms, ulong sources, int termCount, ref ulong result, ref ulong work)
	{
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong extended = ref Unsafe.Add(ref work, Extended);
		ref ulong leftSums = ref Unsafe.Add(ref work, LeftSums);
		ref ulong middle = ref Unsafe.Add(ref work, Combined);
		AddRows(ref a, ref Unsafe.Add(ref a, ComponentLength), ref leftSums);
		Extend(ref b, ref extended, true);

		for (int v = 0; v < VectorCount; ++v)
		{
			Accumulate(ref a, ref extended, terms, sources, termCount, v, ref products, ref middle);
			Accumulate(ref Unsafe.Add(ref a, ComponentLength), ref Unsafe.Add(ref extended, ExtendedLength), terms, sources, termCount, v, ref Unsafe.Add(ref products, WideLength), ref middle);
			Accumulate(ref leftSums, ref Unsafe.Add(ref extended, 2 * ExtendedLength), terms, sources, termCount, v, ref Unsafe.Add(ref products, 2 * WideLength), ref middle);
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref products, v, ref result);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AddRows(ref ulong x, ref ulong y, ref ulong sum)
	{
		for (int i = 0; i < ComponentLength; i += TVector.Count)
		{
			(TVector.Load(in Unsafe.Add(ref x, i)) + TVector.Load(in Unsafe.Add(ref y, i))).Store(ref Unsafe.Add(ref sum, i));
		}
	}

	// The extended rows of b for its three Karatsuba components y0, y1 and y0 + y1: for each limb, u·b = −2y1 + y0·u, with −2y1 as 2(3p − y1), and b from qword ExtendedOrigin, so that the row at qword ExtendedOrigin − i holds b' with b'_k = b_(k−i) for k ≥ i and u·b_(k−i+6) otherwise. Vectors of a whole row store u·b two lanes up at qword 0 and b at qword 8, every store on its own line; narrower ones store u·b at qword 0 and then b over its padding at qword 6. Where halves is set, rows 10 to 14 of each component take the sums of rows m and m + 5, qword by qword, for the products by halves: below 2^30.33, as the rows are below 2^29.33.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Extend(ref ulong b, ref ulong extended, bool halves)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		if (TVector.Count == RowLength)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				ref ulong e0 = ref Unsafe.Add(ref extended, ExtendedRowLength * m);
				ref ulong e1 = ref Unsafe.Add(ref e0, ExtendedLength);
				ref ulong es = ref Unsafe.Add(ref e0, 2 * ExtendedLength);
				TVector y0 = TVector.Load(in Unsafe.Add(ref b, RowLength * m));
				TVector y1 = TVector.Load(in Unsafe.Add(ref b, ComponentLength + RowLength * m));
				TVector w0 = TVector.Create(threeP[m]) - y1 << 1;
				TVector.Permute(w0, w0, TwoLanesUp).Store(ref e0);
				TVector.Permute(y0, y0, TwoLanesUp).Store(ref e1);
				TVector.Permute(w0 + y0, w0 + y0, TwoLanesUp).Store(ref es);
				y0.Store(ref Unsafe.Add(ref e0, RowLength));
				y1.Store(ref Unsafe.Add(ref e1, RowLength));
				(y0 + y1).Store(ref Unsafe.Add(ref es, RowLength));
			}
		}
		else
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				ref ulong b0 = ref Unsafe.Add(ref b, RowLength * m);
				ref ulong b1 = ref Unsafe.Add(ref b0, ComponentLength);
				ref ulong e0 = ref Unsafe.Add(ref extended, ExtendedRowLength * m);
				ref ulong e1 = ref Unsafe.Add(ref e0, ExtendedLength);
				ref ulong es = ref Unsafe.Add(ref e0, 2 * ExtendedLength);
				TVector cover = TVector.Create(threeP[m]);

				for (int i = 0; i < RowLength; i += TVector.Count)
				{
					TVector y0 = TVector.Load(in Unsafe.Add(ref b0, i));
					TVector y1 = TVector.Load(in Unsafe.Add(ref b1, i));
					TVector w0 = cover - y1 << 1;
					w0.Store(ref Unsafe.Add(ref e0, i));
					y0.Store(ref Unsafe.Add(ref e1, i));
					(w0 + y0).Store(ref Unsafe.Add(ref es, i));
				}

				for (int i = 0; i < RowLength; i += TVector.Count)
				{
					TVector y0 = TVector.Load(in Unsafe.Add(ref b0, i));
					TVector y1 = TVector.Load(in Unsafe.Add(ref b1, i));
					y0.Store(ref Unsafe.Add(ref e0, 6 + i));
					y1.Store(ref Unsafe.Add(ref e1, 6 + i));
					(y0 + y1).Store(ref Unsafe.Add(ref es, 6 + i));
				}
			}
		}

		if (!halves)
		{
			return;
		}

		for (int c = 0; c < 3 * ExtendedLength; c += ExtendedLength)
		{
			for (int m = 0; m < HalfLimbs; ++m)
			{
				ref ulong low = ref Unsafe.Add(ref extended, c + ExtendedRowLength * m);

				for (int i = 0; i < ExtendedRowLength; i += TVector.Count)
				{
					(TVector.Load(in Unsafe.Add(ref low, i)) + TVector.Load(in Unsafe.Add(ref low, ExtendedRowLength * HalfLimbs + i))).Store(ref Unsafe.Add(ref low, ExtendedRowLength * LimbCount + i));
				}
			}
		}
	}

	// The products of three terms or more each lane into nineteen columns, by halves, by the kernel that suits the registers of TVector; the narrow one takes nine rows at middle for its sums.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Accumulate(ref ulong left, ref ulong right, ulong terms, ulong sources, int termCount, int v, ref ulong wide, ref ulong middle)
	{
		if (TVector.RegisterCount >= 32)
		{
			AccumulateWide<LaneBroadcast>(ref left, ref right, terms, sources, termCount, v, ref wide);
		}
		else
		{
			int offset = v * TVector.Count;
			AccumulateNarrow(ref left, ref Unsafe.Add(ref right, offset), terms, sources, termCount, ref Unsafe.Add(ref wide, offset), ref Unsafe.Add(ref middle, offset));
		}
	}

	// As Accumulate for the two terms of a normalized line, which do not pay for the sums of the halves on the narrow kernel, so they take whole operands there, as LineHalves says.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateLine(ref ulong left, ref ulong right, ulong sources, int v, ref ulong wide)
	{
		if (LineHalves)
		{
			AccumulateWide<LaneBroadcast>(ref left, ref right, NormalizedLineTerms, sources, 2, v, ref wide);
		}
		else
		{
			AccumulateNarrowWhole(ref left, ref right, NormalizedLineTerms, sources, 2, v, ref wide);
		}
	}

	private static bool LineHalves
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TVector.RegisterCount >= 32;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateLanes(ref ulong left, ref ulong right, int v, ref ulong wide)
	{
		if (TVector.RegisterCount >= 32)
		{
			AccumulateLanesWide(ref left, ref right, v, ref wide);
		}
		else
		{
			AccumulateLanesNarrow(ref left, ref right, v, ref wide);
		}
	}

	private interface IBroadcast
	{
		static abstract TVector Load(ref readonly ulong source);
	}

	private readonly struct LaneBroadcast : IBroadcast
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static TVector Load(ref readonly ulong source)
		{
			return TVector.LoadBroadcast(in source);
		}
	}

	// The terms of the square take the pair of lanes 2i and 2i + 1 of left.
	private readonly struct PairBroadcast : IBroadcast
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static TVector Load(ref readonly ulong source)
		{
			return TVector.LoadPairBroadcast(in source);
		}
	}

	// The 19 columns of Σ_t x·y over the terms, the lanes that terms packs, four bits each, for vector v of the rows: x is the qword of left that sources packs, SourceBits each, in each of ten rows, broadcast by TBroadcast, and y the ten extended rows of right from qword ExtendedOrigin − i for lane i, with the sums of their halves in rows 10 to 14. By Karatsuba on halves of five limbs, x·y = L + (M − L − H)·2^130 + H·2^260 with L = xL·yL, H = xH·yH and M = (xL + xH)(yL + yH), 75 lane products rather than 100: a first pass sums L and H over the terms in eighteen registers, and columns 5 to 13 of L + H·2^260 − (L + H)·2^130 then start the sums of M of a second pass. The columns are those of the whole products, as M − L − H is exact modulo 2^64.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AccumulateWide<TBroadcast>(ref ulong left, ref ulong right, ulong terms, ulong sources, int termCount, int v, ref ulong wide) where TBroadcast : struct, IBroadcast
	{
		TVector l0 = TVector.Zero;
		TVector l1 = TVector.Zero;
		TVector l2 = TVector.Zero;
		TVector l3 = TVector.Zero;
		TVector l4 = TVector.Zero;
		TVector l5 = TVector.Zero;
		TVector l6 = TVector.Zero;
		TVector l7 = TVector.Zero;
		TVector l8 = TVector.Zero;
		TVector h0 = TVector.Zero;
		TVector h1 = TVector.Zero;
		TVector h2 = TVector.Zero;
		TVector h3 = TVector.Zero;
		TVector h4 = TVector.Zero;
		TVector h5 = TVector.Zero;
		TVector h6 = TVector.Zero;
		TVector h7 = TVector.Zero;
		TVector h8 = TVector.Zero;
		wide = ref Unsafe.Add(ref wide, v * TVector.Count);

		for (int t = 0; t < termCount; ++t)
		{
			int i = (int)(terms >> 4 * t) & 15;
			ref ulong x = ref Unsafe.Add(ref left, Source(sources, t));
			ref ulong y = ref Unsafe.Add(ref right, ExtendedOrigin - i + v * TVector.Count);
			TVector y0 = TVector.Load(in y);
			TVector y1 = TVector.Load(in Unsafe.Add(ref y, 16));
			TVector y2 = TVector.Load(in Unsafe.Add(ref y, 32));
			TVector y3 = TVector.Load(in Unsafe.Add(ref y, 48));
			TVector y4 = TVector.Load(in Unsafe.Add(ref y, 64));
			TVector x0 = TBroadcast.Load(in x);
			l0 = TVector.MultiplyAdd(l0, x0, y0);
			l1 = TVector.MultiplyAdd(l1, x0, y1);
			l2 = TVector.MultiplyAdd(l2, x0, y2);
			l3 = TVector.MultiplyAdd(l3, x0, y3);
			l4 = TVector.MultiplyAdd(l4, x0, y4);
			TVector x1 = TBroadcast.Load(in Unsafe.Add(ref x, 8));
			l1 = TVector.MultiplyAdd(l1, x1, y0);
			l2 = TVector.MultiplyAdd(l2, x1, y1);
			l3 = TVector.MultiplyAdd(l3, x1, y2);
			l4 = TVector.MultiplyAdd(l4, x1, y3);
			l5 = TVector.MultiplyAdd(l5, x1, y4);
			TVector x2 = TBroadcast.Load(in Unsafe.Add(ref x, 16));
			l2 = TVector.MultiplyAdd(l2, x2, y0);
			l3 = TVector.MultiplyAdd(l3, x2, y1);
			l4 = TVector.MultiplyAdd(l4, x2, y2);
			l5 = TVector.MultiplyAdd(l5, x2, y3);
			l6 = TVector.MultiplyAdd(l6, x2, y4);
			TVector x3 = TBroadcast.Load(in Unsafe.Add(ref x, 24));
			l3 = TVector.MultiplyAdd(l3, x3, y0);
			l4 = TVector.MultiplyAdd(l4, x3, y1);
			l5 = TVector.MultiplyAdd(l5, x3, y2);
			l6 = TVector.MultiplyAdd(l6, x3, y3);
			l7 = TVector.MultiplyAdd(l7, x3, y4);
			TVector x4 = TBroadcast.Load(in Unsafe.Add(ref x, 32));
			l4 = TVector.MultiplyAdd(l4, x4, y0);
			l5 = TVector.MultiplyAdd(l5, x4, y1);
			l6 = TVector.MultiplyAdd(l6, x4, y2);
			l7 = TVector.MultiplyAdd(l7, x4, y3);
			l8 = TVector.MultiplyAdd(l8, x4, y4);
			TVector y5 = TVector.Load(in Unsafe.Add(ref y, 80));
			TVector y6 = TVector.Load(in Unsafe.Add(ref y, 96));
			TVector y7 = TVector.Load(in Unsafe.Add(ref y, 112));
			TVector y8 = TVector.Load(in Unsafe.Add(ref y, 128));
			TVector y9 = TVector.Load(in Unsafe.Add(ref y, 144));
			TVector x5 = TBroadcast.Load(in Unsafe.Add(ref x, 40));
			h0 = TVector.MultiplyAdd(h0, x5, y5);
			h1 = TVector.MultiplyAdd(h1, x5, y6);
			h2 = TVector.MultiplyAdd(h2, x5, y7);
			h3 = TVector.MultiplyAdd(h3, x5, y8);
			h4 = TVector.MultiplyAdd(h4, x5, y9);
			TVector x6 = TBroadcast.Load(in Unsafe.Add(ref x, 48));
			h1 = TVector.MultiplyAdd(h1, x6, y5);
			h2 = TVector.MultiplyAdd(h2, x6, y6);
			h3 = TVector.MultiplyAdd(h3, x6, y7);
			h4 = TVector.MultiplyAdd(h4, x6, y8);
			h5 = TVector.MultiplyAdd(h5, x6, y9);
			TVector x7 = TBroadcast.Load(in Unsafe.Add(ref x, 56));
			h2 = TVector.MultiplyAdd(h2, x7, y5);
			h3 = TVector.MultiplyAdd(h3, x7, y6);
			h4 = TVector.MultiplyAdd(h4, x7, y7);
			h5 = TVector.MultiplyAdd(h5, x7, y8);
			h6 = TVector.MultiplyAdd(h6, x7, y9);
			TVector x8 = TBroadcast.Load(in Unsafe.Add(ref x, 64));
			h3 = TVector.MultiplyAdd(h3, x8, y5);
			h4 = TVector.MultiplyAdd(h4, x8, y6);
			h5 = TVector.MultiplyAdd(h5, x8, y7);
			h6 = TVector.MultiplyAdd(h6, x8, y8);
			h7 = TVector.MultiplyAdd(h7, x8, y9);
			TVector x9 = TBroadcast.Load(in Unsafe.Add(ref x, 72));
			h4 = TVector.MultiplyAdd(h4, x9, y5);
			h5 = TVector.MultiplyAdd(h5, x9, y6);
			h6 = TVector.MultiplyAdd(h6, x9, y7);
			h7 = TVector.MultiplyAdd(h7, x9, y8);
			h8 = TVector.MultiplyAdd(h8, x9, y9);
		}

		l0.Store(ref wide);
		l1.Store(ref Unsafe.Add(ref wide, 8));
		l2.Store(ref Unsafe.Add(ref wide, 16));
		l3.Store(ref Unsafe.Add(ref wide, 24));
		l4.Store(ref Unsafe.Add(ref wide, 32));
		h4.Store(ref Unsafe.Add(ref wide, 112));
		h5.Store(ref Unsafe.Add(ref wide, 120));
		h6.Store(ref Unsafe.Add(ref wide, 128));
		h7.Store(ref Unsafe.Add(ref wide, 136));
		h8.Store(ref Unsafe.Add(ref wide, 144));
		TVector m0 = l5 - l0 - h0;
		TVector m1 = l6 - l1 - h1;
		TVector m2 = l7 - l2 - h2;
		TVector m3 = l8 - l3 - h3;
		TVector m4 = TVector.Zero - l4 - h4;
		TVector m5 = h0 - l5 - h5;
		TVector m6 = h1 - l6 - h6;
		TVector m7 = h2 - l7 - h7;
		TVector m8 = h3 - l8 - h8;

		for (int t = 0; t < termCount; ++t)
		{
			int i = (int)(terms >> 4 * t) & 15;
			ref ulong x = ref Unsafe.Add(ref left, Source(sources, t));
			ref ulong y = ref Unsafe.Add(ref right, ExtendedOrigin - i + v * TVector.Count + ExtendedRowLength * LimbCount);
			TVector s0 = TVector.Load(in y);
			TVector s1 = TVector.Load(in Unsafe.Add(ref y, 16));
			TVector s2 = TVector.Load(in Unsafe.Add(ref y, 32));
			TVector s3 = TVector.Load(in Unsafe.Add(ref y, 48));
			TVector s4 = TVector.Load(in Unsafe.Add(ref y, 64));
			TVector x0 = TBroadcast.Load(in x) + TBroadcast.Load(in Unsafe.Add(ref x, 40));
			m0 = TVector.MultiplyAdd(m0, x0, s0);
			m1 = TVector.MultiplyAdd(m1, x0, s1);
			m2 = TVector.MultiplyAdd(m2, x0, s2);
			m3 = TVector.MultiplyAdd(m3, x0, s3);
			m4 = TVector.MultiplyAdd(m4, x0, s4);
			TVector x1 = TBroadcast.Load(in Unsafe.Add(ref x, 8)) + TBroadcast.Load(in Unsafe.Add(ref x, 48));
			m1 = TVector.MultiplyAdd(m1, x1, s0);
			m2 = TVector.MultiplyAdd(m2, x1, s1);
			m3 = TVector.MultiplyAdd(m3, x1, s2);
			m4 = TVector.MultiplyAdd(m4, x1, s3);
			m5 = TVector.MultiplyAdd(m5, x1, s4);
			TVector x2 = TBroadcast.Load(in Unsafe.Add(ref x, 16)) + TBroadcast.Load(in Unsafe.Add(ref x, 56));
			m2 = TVector.MultiplyAdd(m2, x2, s0);
			m3 = TVector.MultiplyAdd(m3, x2, s1);
			m4 = TVector.MultiplyAdd(m4, x2, s2);
			m5 = TVector.MultiplyAdd(m5, x2, s3);
			m6 = TVector.MultiplyAdd(m6, x2, s4);
			TVector x3 = TBroadcast.Load(in Unsafe.Add(ref x, 24)) + TBroadcast.Load(in Unsafe.Add(ref x, 64));
			m3 = TVector.MultiplyAdd(m3, x3, s0);
			m4 = TVector.MultiplyAdd(m4, x3, s1);
			m5 = TVector.MultiplyAdd(m5, x3, s2);
			m6 = TVector.MultiplyAdd(m6, x3, s3);
			m7 = TVector.MultiplyAdd(m7, x3, s4);
			TVector x4 = TBroadcast.Load(in Unsafe.Add(ref x, 32)) + TBroadcast.Load(in Unsafe.Add(ref x, 72));
			m4 = TVector.MultiplyAdd(m4, x4, s0);
			m5 = TVector.MultiplyAdd(m5, x4, s1);
			m6 = TVector.MultiplyAdd(m6, x4, s2);
			m7 = TVector.MultiplyAdd(m7, x4, s3);
			m8 = TVector.MultiplyAdd(m8, x4, s4);
		}

		m0.Store(ref Unsafe.Add(ref wide, 40));
		m1.Store(ref Unsafe.Add(ref wide, 48));
		m2.Store(ref Unsafe.Add(ref wide, 56));
		m3.Store(ref Unsafe.Add(ref wide, 64));
		m4.Store(ref Unsafe.Add(ref wide, 72));
		m5.Store(ref Unsafe.Add(ref wide, 80));
		m6.Store(ref Unsafe.Add(ref wide, 88));
		m7.Store(ref Unsafe.Add(ref wide, 96));
		m8.Store(ref Unsafe.Add(ref wide, 104));
	}

	// The 19 columns of the lane products x·y of the ten rows of left and of right, for vector v, by the halves of AccumulateWide: L and H first, then M from the sums of the halves of x and y, below 2^32 for the limbs below 2^31 that the callers take, which starts from columns 5 to 13 of L + H·2^260 − (L + H)·2^130.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AccumulateLanesWide(ref ulong left, ref ulong right, int v, ref ulong wide)
	{
		wide = ref Unsafe.Add(ref wide, v * TVector.Count);
		ref ulong x = ref Unsafe.Add(ref left, v * TVector.Count);
		ref ulong y = ref Unsafe.Add(ref right, v * TVector.Count);
		TVector y0 = TVector.Load(in y);
		TVector y1 = TVector.Load(in Unsafe.Add(ref y, 8));
		TVector y2 = TVector.Load(in Unsafe.Add(ref y, 16));
		TVector y3 = TVector.Load(in Unsafe.Add(ref y, 24));
		TVector y4 = TVector.Load(in Unsafe.Add(ref y, 32));
		TVector x0 = TVector.Load(in x);
		TVector l0 = TVector.Multiply(x0, y0);
		TVector l1 = TVector.Multiply(x0, y1);
		TVector l2 = TVector.Multiply(x0, y2);
		TVector l3 = TVector.Multiply(x0, y3);
		TVector l4 = TVector.Multiply(x0, y4);
		TVector x1 = TVector.Load(in Unsafe.Add(ref x, 8));
		l1 = TVector.MultiplyAdd(l1, x1, y0);
		l2 = TVector.MultiplyAdd(l2, x1, y1);
		l3 = TVector.MultiplyAdd(l3, x1, y2);
		l4 = TVector.MultiplyAdd(l4, x1, y3);
		TVector l5 = TVector.Multiply(x1, y4);
		TVector x2 = TVector.Load(in Unsafe.Add(ref x, 16));
		l2 = TVector.MultiplyAdd(l2, x2, y0);
		l3 = TVector.MultiplyAdd(l3, x2, y1);
		l4 = TVector.MultiplyAdd(l4, x2, y2);
		l5 = TVector.MultiplyAdd(l5, x2, y3);
		TVector l6 = TVector.Multiply(x2, y4);
		TVector x3 = TVector.Load(in Unsafe.Add(ref x, 24));
		l3 = TVector.MultiplyAdd(l3, x3, y0);
		l4 = TVector.MultiplyAdd(l4, x3, y1);
		l5 = TVector.MultiplyAdd(l5, x3, y2);
		l6 = TVector.MultiplyAdd(l6, x3, y3);
		TVector l7 = TVector.Multiply(x3, y4);
		TVector x4 = TVector.Load(in Unsafe.Add(ref x, 32));
		l4 = TVector.MultiplyAdd(l4, x4, y0);
		l5 = TVector.MultiplyAdd(l5, x4, y1);
		l6 = TVector.MultiplyAdd(l6, x4, y2);
		l7 = TVector.MultiplyAdd(l7, x4, y3);
		TVector l8 = TVector.Multiply(x4, y4);
		TVector y5 = TVector.Load(in Unsafe.Add(ref y, 40));
		TVector y6 = TVector.Load(in Unsafe.Add(ref y, 48));
		TVector y7 = TVector.Load(in Unsafe.Add(ref y, 56));
		TVector y8 = TVector.Load(in Unsafe.Add(ref y, 64));
		TVector y9 = TVector.Load(in Unsafe.Add(ref y, 72));
		TVector x5 = TVector.Load(in Unsafe.Add(ref x, 40));
		TVector h0 = TVector.Multiply(x5, y5);
		TVector h1 = TVector.Multiply(x5, y6);
		TVector h2 = TVector.Multiply(x5, y7);
		TVector h3 = TVector.Multiply(x5, y8);
		TVector h4 = TVector.Multiply(x5, y9);
		TVector x6 = TVector.Load(in Unsafe.Add(ref x, 48));
		h1 = TVector.MultiplyAdd(h1, x6, y5);
		h2 = TVector.MultiplyAdd(h2, x6, y6);
		h3 = TVector.MultiplyAdd(h3, x6, y7);
		h4 = TVector.MultiplyAdd(h4, x6, y8);
		TVector h5 = TVector.Multiply(x6, y9);
		TVector x7 = TVector.Load(in Unsafe.Add(ref x, 56));
		h2 = TVector.MultiplyAdd(h2, x7, y5);
		h3 = TVector.MultiplyAdd(h3, x7, y6);
		h4 = TVector.MultiplyAdd(h4, x7, y7);
		h5 = TVector.MultiplyAdd(h5, x7, y8);
		TVector h6 = TVector.Multiply(x7, y9);
		TVector x8 = TVector.Load(in Unsafe.Add(ref x, 64));
		h3 = TVector.MultiplyAdd(h3, x8, y5);
		h4 = TVector.MultiplyAdd(h4, x8, y6);
		h5 = TVector.MultiplyAdd(h5, x8, y7);
		h6 = TVector.MultiplyAdd(h6, x8, y8);
		TVector h7 = TVector.Multiply(x8, y9);
		TVector x9 = TVector.Load(in Unsafe.Add(ref x, 72));
		h4 = TVector.MultiplyAdd(h4, x9, y5);
		h5 = TVector.MultiplyAdd(h5, x9, y6);
		h6 = TVector.MultiplyAdd(h6, x9, y7);
		h7 = TVector.MultiplyAdd(h7, x9, y8);
		TVector h8 = TVector.Multiply(x9, y9);
		l0.Store(ref wide);
		l1.Store(ref Unsafe.Add(ref wide, 8));
		l2.Store(ref Unsafe.Add(ref wide, 16));
		l3.Store(ref Unsafe.Add(ref wide, 24));
		l4.Store(ref Unsafe.Add(ref wide, 32));
		h4.Store(ref Unsafe.Add(ref wide, 112));
		h5.Store(ref Unsafe.Add(ref wide, 120));
		h6.Store(ref Unsafe.Add(ref wide, 128));
		h7.Store(ref Unsafe.Add(ref wide, 136));
		h8.Store(ref Unsafe.Add(ref wide, 144));
		TVector m0 = l5 - l0 - h0;
		TVector m1 = l6 - l1 - h1;
		TVector m2 = l7 - l2 - h2;
		TVector m3 = l8 - l3 - h3;
		TVector m4 = TVector.Zero - l4 - h4;
		TVector m5 = h0 - l5 - h5;
		TVector m6 = h1 - l6 - h6;
		TVector m7 = h2 - l7 - h7;
		TVector m8 = h3 - l8 - h8;
		TVector s0 = TVector.Load(in y) + TVector.Load(in Unsafe.Add(ref y, 40));
		TVector s1 = TVector.Load(in Unsafe.Add(ref y, 8)) + TVector.Load(in Unsafe.Add(ref y, 48));
		TVector s2 = TVector.Load(in Unsafe.Add(ref y, 16)) + TVector.Load(in Unsafe.Add(ref y, 56));
		TVector s3 = TVector.Load(in Unsafe.Add(ref y, 24)) + TVector.Load(in Unsafe.Add(ref y, 64));
		TVector s4 = TVector.Load(in Unsafe.Add(ref y, 32)) + TVector.Load(in Unsafe.Add(ref y, 72));
		TVector z0 = TVector.Load(in x) + TVector.Load(in Unsafe.Add(ref x, 40));
		m0 = TVector.MultiplyAdd(m0, z0, s0);
		m1 = TVector.MultiplyAdd(m1, z0, s1);
		m2 = TVector.MultiplyAdd(m2, z0, s2);
		m3 = TVector.MultiplyAdd(m3, z0, s3);
		m4 = TVector.MultiplyAdd(m4, z0, s4);
		TVector z1 = TVector.Load(in Unsafe.Add(ref x, 8)) + TVector.Load(in Unsafe.Add(ref x, 48));
		m1 = TVector.MultiplyAdd(m1, z1, s0);
		m2 = TVector.MultiplyAdd(m2, z1, s1);
		m3 = TVector.MultiplyAdd(m3, z1, s2);
		m4 = TVector.MultiplyAdd(m4, z1, s3);
		m5 = TVector.MultiplyAdd(m5, z1, s4);
		TVector z2 = TVector.Load(in Unsafe.Add(ref x, 16)) + TVector.Load(in Unsafe.Add(ref x, 56));
		m2 = TVector.MultiplyAdd(m2, z2, s0);
		m3 = TVector.MultiplyAdd(m3, z2, s1);
		m4 = TVector.MultiplyAdd(m4, z2, s2);
		m5 = TVector.MultiplyAdd(m5, z2, s3);
		m6 = TVector.MultiplyAdd(m6, z2, s4);
		TVector z3 = TVector.Load(in Unsafe.Add(ref x, 24)) + TVector.Load(in Unsafe.Add(ref x, 64));
		m3 = TVector.MultiplyAdd(m3, z3, s0);
		m4 = TVector.MultiplyAdd(m4, z3, s1);
		m5 = TVector.MultiplyAdd(m5, z3, s2);
		m6 = TVector.MultiplyAdd(m6, z3, s3);
		m7 = TVector.MultiplyAdd(m7, z3, s4);
		TVector z4 = TVector.Load(in Unsafe.Add(ref x, 32)) + TVector.Load(in Unsafe.Add(ref x, 72));
		m4 = TVector.MultiplyAdd(m4, z4, s0);
		m5 = TVector.MultiplyAdd(m5, z4, s1);
		m6 = TVector.MultiplyAdd(m6, z4, s2);
		m7 = TVector.MultiplyAdd(m7, z4, s3);
		m8 = TVector.MultiplyAdd(m8, z4, s4);
		m0.Store(ref Unsafe.Add(ref wide, 40));
		m1.Store(ref Unsafe.Add(ref wide, 48));
		m2.Store(ref Unsafe.Add(ref wide, 56));
		m3.Store(ref Unsafe.Add(ref wide, 64));
		m4.Store(ref Unsafe.Add(ref wide, 72));
		m5.Store(ref Unsafe.Add(ref wide, 80));
		m6.Store(ref Unsafe.Add(ref wide, 88));
		m7.Store(ref Unsafe.Add(ref wide, 96));
		m8.Store(ref Unsafe.Add(ref wide, 104));
	}

	// c0 = P0 − 2P1 + 64p² and c1 = Ps − P0 − P1 from the products at products, reduced into the two components of result, for vector v. With 32 registers the columns go into the rounds of Reduce2Wide as they form instead of through memory, the same columns and so the same results; the narrower vectors store them for Reduce2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceProducts(ref ulong products, int v, ref ulong result)
	{
		ReduceProducts(ref products, false, ref products, v, ref result);
	}

	// As ReduceProducts with c0 and c1 taking x·R as well where hasUnit is set, for x the extended rows at unit, its real part in the first set and its u-part in the second, ExtendedLength apart: limb m of x goes into column 10 + m, R = 2^260, so that the reduction adds x to the result. For each width one unit of code serves both, its branches following hasUnit alone; the width picks the unit here, so that neither unit takes the code of the other into its budget of inlining.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ReduceProducts(ref ulong products, bool hasUnit, ref ulong unit, int v, ref ulong result)
	{
		if (TVector.RegisterCount >= 32)
		{
			ReduceColumnsWide(ref products, hasUnit, ref unit, v, ref result);
		}
		else
		{
			ReduceColumns(ref products, hasUnit, ref unit, v, ref result);
		}
	}

	// ReduceProducts for the narrower vectors: the columns go back into the products for Reduce2.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ReduceColumns(ref ulong products, bool hasUnit, ref ulong unit, int v, ref ulong result)
	{
		ref ulong x0 = ref Unsafe.Add(ref products, v * TVector.Count);
		ref ulong x1 = ref Unsafe.Add(ref x0, WideLength);
		ref ulong xs = ref Unsafe.Add(ref x0, 2 * WideLength);
		ref ulong unitReal = ref Unsafe.Add(ref unit, v * TVector.Count);
		ref ulong unitImaginary = ref Unsafe.Add(ref unitReal, ExtendedLength);
		ReadOnlySpan<ulong> offset = Offset;

		for (int s = 0; s < WideRows - 1; ++s)
		{
			TVector p0 = TVector.Load(in Unsafe.Add(ref x0, RowLength * s));
			TVector p1 = TVector.Load(in Unsafe.Add(ref x1, RowLength * s));
			TVector ps = TVector.Load(in Unsafe.Add(ref xs, RowLength * s));
			TVector c0 = p0 - (p1 << 1) + TVector.Create(offset[s]);
			TVector c1 = ps - p0 - p1;

			if (hasUnit && s >= LimbCount)
			{
				c0 += TVector.Load(in Unsafe.Add(ref unitReal, ExtendedRowLength * (s - LimbCount)));
				c1 += TVector.Load(in Unsafe.Add(ref unitImaginary, ExtendedRowLength * (s - LimbCount)));
			}

			c0.Store(ref Unsafe.Add(ref x0, RowLength * s));
			c1.Store(ref Unsafe.Add(ref x1, RowLength * s));
		}

		TVector top0 = TVector.Create(offset[WideRows - 1]);
		TVector top1 = TVector.Zero;

		if (hasUnit)
		{
			top0 += TVector.Load(in Unsafe.Add(ref unitReal, ExtendedRowLength * (LimbCount - 1)));
			top1 = TVector.Load(in Unsafe.Add(ref unitImaginary, ExtendedRowLength * (LimbCount - 1)));
		}

		top0.Store(ref Unsafe.Add(ref x0, RowLength * (WideRows - 1)));
		top1.Store(ref Unsafe.Add(ref x1, RowLength * (WideRows - 1)));
		Reduce2(ref x0, ref x1, ref Unsafe.Add(ref result, v * TVector.Count), ref Unsafe.Add(ref result, ComponentLength + v * TVector.Count));
	}

	// ReduceProducts with 32 registers: the rounds of Reduce2Wide on c0 = P0 − 2P1 + 64p² and c1 = Ps − P0 − P1, each column formed as the window takes it in, with the limbs of the unit term from column 10 on if there is one; column 19 of the products is 0, so its columns are the digit of 64p² and 0 with that of the unit term.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ReduceColumnsWide(ref ulong products, bool hasUnit, ref ulong unit, int v, ref ulong destination)
	{
		ref ulong x0 = ref Unsafe.Add(ref products, v * TVector.Count);
		ref ulong x1 = ref Unsafe.Add(ref x0, WideLength);
		ref ulong xs = ref Unsafe.Add(ref x0, 2 * WideLength);
		ref ulong unitReal = ref Unsafe.Add(ref unit, v * TVector.Count);
		ref ulong unitImaginary = ref Unsafe.Add(ref unitReal, ExtendedLength);
		ref ulong result = ref Unsafe.Add(ref destination, v * TVector.Count);
		ref ulong resultB = ref Unsafe.Add(ref destination, ComponentLength + v * TVector.Count);
		ReadOnlySpan<ulong> offset = Offset;
		TVector mask = TVector.Create(Mask);
		TVector inverse = TVector.Create(NegativeInverse);
		Column(ref x0, ref x1, ref xs, offset, 0, out TVector t0, out TVector u0);
		Column(ref x0, ref x1, ref xs, offset, 1, out TVector t1, out TVector u1);
		Column(ref x0, ref x1, ref xs, offset, 2, out TVector t2, out TVector u2);
		Column(ref x0, ref x1, ref xs, offset, 3, out TVector t3, out TVector u3);
		Column(ref x0, ref x1, ref xs, offset, 4, out TVector t4, out TVector u4);
		Column(ref x0, ref x1, ref xs, offset, 5, out TVector t5, out TVector u5);
		Column(ref x0, ref x1, ref xs, offset, 6, out TVector t6, out TVector u6);
		Column(ref x0, ref x1, ref xs, offset, 7, out TVector t7, out TVector u7);
		Column(ref x0, ref x1, ref xs, offset, 8, out TVector t8, out TVector u8);
		Column(ref x0, ref x1, ref xs, offset, 9, out TVector t9, out TVector u9);

		for (int k = 0; k < 10; ++k)
		{
			TVector q = TVector.Multiply(t0, inverse) & mask;
			TVector r = TVector.Multiply(u0, inverse) & mask;
			t0 = t1 + TVector.ShiftRightArithmetic26(t0 + mask) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
			u0 = u1 + TVector.ShiftRightArithmetic26(u0 + mask) + TVector.MultiplyByFactor(r, P1) + (TVector.MultiplyByFactor(r, P0) >>> 26);
			t1 = t2 + TVector.MultiplyByFactor(q, P2);
			u1 = u2 + TVector.MultiplyByFactor(r, P2);
			t2 = t3 + TVector.MultiplyByFactor(q, P3);
			u2 = u3 + TVector.MultiplyByFactor(r, P3);
			t3 = t4 + TVector.MultiplyByFactor(q, P4);
			u3 = u4 + TVector.MultiplyByFactor(r, P4);
			t4 = t5 + TVector.MultiplyByFactor(q, P5);
			u4 = u5 + TVector.MultiplyByFactor(r, P5);
			t5 = t6 + TVector.MultiplyByFactor(q, P6);
			u5 = u6 + TVector.MultiplyByFactor(r, P6);
			t6 = t7 + TVector.MultiplyByFactor(q, P7);
			u6 = u7 + TVector.MultiplyByFactor(r, P7);
			t7 = t8 + TVector.MultiplyByFactor(q, P8);
			u7 = u8 + TVector.MultiplyByFactor(r, P8);
			t8 = t9 + TVector.MultiplyByFactor(q, P9);
			u8 = u9 + TVector.MultiplyByFactor(r, P9);

			if (k < 9)
			{
				Column(ref x0, ref x1, ref xs, offset, k + 10, out t9, out u9);
			}
			else
			{
				t9 = TVector.Create(offset[WideRows - 1]);
				u9 = TVector.Zero;
			}

			if (hasUnit)
			{
				t9 += TVector.Load(in Unsafe.Add(ref unitReal, ExtendedRowLength * k));
				u9 += TVector.Load(in Unsafe.Add(ref unitImaginary, ExtendedRowLength * k));
			}
		}

		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		Carry(ref u0, ref u1, ref u2, ref u3, ref u4, ref u5, ref u6, ref u7, ref u8, ref u9);
		Store(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
		Store(u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ref resultB);
		WeakReduce2(ref result, ref resultB);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Column(ref ulong x0, ref ulong x1, ref ulong xs, ReadOnlySpan<ulong> offset, int s, out TVector c0, out TVector c1)
	{
		TVector p0 = TVector.Load(in Unsafe.Add(ref x0, RowLength * s));
		TVector p1 = TVector.Load(in Unsafe.Add(ref x1, RowLength * s));
		c0 = p0 - (p1 << 1) + TVector.Create(offset[s]);
		c1 = TVector.Load(in Unsafe.Add(ref xs, RowLength * s)) - p0 - p1;
	}

	// The square of an element of the cyclotomic subgroup by the formula of SM9Fp12.CyclotomicSquare. Its Fp4 = Fp2[V], V = w³, are the pairs of lanes j and j + 3, X0 + X1·V, whose squares (X0² + u·X1², 2X0X1) take m = X0·X1 in lane j and n = (X0 + X1)(X0 + u·X1) in lane j + 3: X0² + u·X1² = n − (1 + u)·m. The square is then (3c² − 2c̄) + (3V·a² + 2b̄)·w + (3b² − 2ā)·w², so output lane k takes 3T_k + 2a_k for the odd lanes and 3T_k − 2a_k for the even ones, with T = (S0_0, u·S1_2, S0_1, S1_0, S0_2, S1_1) from S0_j = n_j − (1 + u)m_j and S1_j = 2m_j, which a permutation of the products gives before their reduction.
	// The operands of n are below 4.5p and 8.25p, with limbs below 2^27 and 2^28.33, so the columns of the products stay below 2^60.3 in magnitude. AVX-512 permutes the columns into those of T, whose values lie in (−45.6p², 67.5p²), T + 64p² below 132p², and columns below 2^62 in magnitude, and reduces them in ReduceCyclotomic; the narrower vectors reduce m and n, products of reduced inputs and their sums, as any product, and permute their rows in CombineCyclotomicRows.
	[SkipLocalsInit]
	internal static void CyclotomicSquare(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		ref ulong a = ref value[0];
		ref ulong work = ref scratch[0];
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong operands = ref Unsafe.Add(ref work, Operands);
		ref ulong square = ref Unsafe.Add(ref work, Temporary);
		ref ulong combined = ref Unsafe.Add(ref work, Combined);
		PrepareCyclotomic(ref a, ref operands, ref square);
		AccumulateOperands(ref operands, ref products);

		ref ulong r = ref result[0];

		if (typeof(TVector) == typeof(SM9VectorAvx512))
		{
			CombineCyclotomic(ref products, ref combined);
			ReduceCyclotomic(ref combined, ref a, ref r);
			return;
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref products, v, ref square);
		}

		CombineCyclotomicRows(ref square, ref a, ref r, ref Unsafe.Add(ref work, Permuted));
		WeakReduceElement(ref r);
	}

	// The rest of the cyclotomic square for AVX-512 from the columns of T that CombineCyclotomic leaves in memory: the rounds of Reduce2Wide keep their windows in registers, and their result S, below 132p²/R + p < 6.88p, goes on in registers to CompleteCyclotomic, without a weak reduction of its own, which would only change the representative of the same value. a is read before result is written, so they may be the same.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ReduceCyclotomic(ref ulong columns, ref ulong a, ref ulong result)
	{
		TVector mask = TVector.Create(Mask);
		TVector inverse = TVector.Create(NegativeInverse);
		ref ulong columnsB = ref Unsafe.Add(ref columns, WideLength);
		TVector t0 = TVector.Load(in columns);
		TVector t1 = TVector.Load(in Unsafe.Add(ref columns, 8));
		TVector t2 = TVector.Load(in Unsafe.Add(ref columns, 16));
		TVector t3 = TVector.Load(in Unsafe.Add(ref columns, 24));
		TVector t4 = TVector.Load(in Unsafe.Add(ref columns, 32));
		TVector t5 = TVector.Load(in Unsafe.Add(ref columns, 40));
		TVector t6 = TVector.Load(in Unsafe.Add(ref columns, 48));
		TVector t7 = TVector.Load(in Unsafe.Add(ref columns, 56));
		TVector t8 = TVector.Load(in Unsafe.Add(ref columns, 64));
		TVector t9 = TVector.Load(in Unsafe.Add(ref columns, 72));
		TVector u0 = TVector.Load(in columnsB);
		TVector u1 = TVector.Load(in Unsafe.Add(ref columnsB, 8));
		TVector u2 = TVector.Load(in Unsafe.Add(ref columnsB, 16));
		TVector u3 = TVector.Load(in Unsafe.Add(ref columnsB, 24));
		TVector u4 = TVector.Load(in Unsafe.Add(ref columnsB, 32));
		TVector u5 = TVector.Load(in Unsafe.Add(ref columnsB, 40));
		TVector u6 = TVector.Load(in Unsafe.Add(ref columnsB, 48));
		TVector u7 = TVector.Load(in Unsafe.Add(ref columnsB, 56));
		TVector u8 = TVector.Load(in Unsafe.Add(ref columnsB, 64));
		TVector u9 = TVector.Load(in Unsafe.Add(ref columnsB, 72));
		ref ulong next = ref Unsafe.Add(ref columns, 80);
		ref ulong nextB = ref Unsafe.Add(ref columnsB, 80);

		for (int k = 0; k < 10; ++k)
		{
			TVector q = TVector.Multiply(t0, inverse) & mask;
			TVector r = TVector.Multiply(u0, inverse) & mask;
			t0 = t1 + TVector.ShiftRightArithmetic26(t0 + mask) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
			u0 = u1 + TVector.ShiftRightArithmetic26(u0 + mask) + TVector.MultiplyByFactor(r, P1) + (TVector.MultiplyByFactor(r, P0) >>> 26);
			t1 = t2 + TVector.MultiplyByFactor(q, P2);
			u1 = u2 + TVector.MultiplyByFactor(r, P2);
			t2 = t3 + TVector.MultiplyByFactor(q, P3);
			u2 = u3 + TVector.MultiplyByFactor(r, P3);
			t3 = t4 + TVector.MultiplyByFactor(q, P4);
			u3 = u4 + TVector.MultiplyByFactor(r, P4);
			t4 = t5 + TVector.MultiplyByFactor(q, P5);
			u4 = u5 + TVector.MultiplyByFactor(r, P5);
			t5 = t6 + TVector.MultiplyByFactor(q, P6);
			u5 = u6 + TVector.MultiplyByFactor(r, P6);
			t6 = t7 + TVector.MultiplyByFactor(q, P7);
			u6 = u7 + TVector.MultiplyByFactor(r, P7);
			t7 = t8 + TVector.MultiplyByFactor(q, P8);
			u7 = u8 + TVector.MultiplyByFactor(r, P8);
			t8 = t9 + TVector.MultiplyByFactor(q, P9);
			u8 = u9 + TVector.MultiplyByFactor(r, P9);
			t9 = TVector.Load(in next);
			u9 = TVector.Load(in nextB);
			next = ref Unsafe.Add(ref next, 8);
			nextB = ref Unsafe.Add(ref nextB, 8);
		}

		CompleteCyclotomic(Avx512(t0), Avx512(t1), Avx512(t2), Avx512(t3), Avx512(t4), Avx512(t5), Avx512(t6), Avx512(t7), Avx512(t8), Avx512(t9), ref a, ref result);
		CompleteCyclotomic(Avx512(u0), Avx512(u1), Avx512(u2), Avx512(u3), Avx512(u4), Avx512(u5), Avx512(u6), Avx512(u7), Avx512(u8), Avx512(u9), ref Unsafe.Add(ref a, ComponentLength), ref Unsafe.Add(ref result, ComponentLength));
	}

	// The vector of AVX-512 that TVector is, for the tails that take the operations of AVX-512 itself, as those of TVector would leave the inliner no room for them in the methods of the rounds.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> Avx512(TVector value)
	{
		return Unsafe.BitCast<TVector, Vector512<ulong>>(value);
	}

	// Carry, then WeakReduce into result, of the ten limbs t as the rounds of a reduction leave them, on AVX-512 itself: the same operations as Carry, Store and WeakReduce2, so the same limbs, without the round trip through result.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CarryAndReduce(Vector512<ulong> t0, Vector512<ulong> t1, Vector512<ulong> t2, Vector512<ulong> t3, Vector512<ulong> t4, Vector512<ulong> t5, Vector512<ulong> t6, Vector512<ulong> t7, Vector512<ulong> t8, Vector512<ulong> t9, ref ulong result)
	{
		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, MultiplyLimb(t9, QuotientMultiplier) >>> 40, ref result);
	}

	// The rest of the cyclotomic square on one component of S in the limbs s, written to the same component of result, on AVX-512 itself: S carried, then F = 3S + 2(3p − a) on the even lanes and 3S + 2a on the odd ones, whose limbs 0 to 8 lie in [0, 7·2^26) and whose value is below 26.7p < 2^260.3, then F weakly reduced as WeakReduce does, the chain of its subtraction carrying F as it goes and the quotient taken from E = F9 + ⌊F8/2^26⌋ in place of the top limb L9 of F carried.
	// The limbs below F8 add below 2^211 to F8·2^208, so L9 is E or E + 1. For E = L9 the bound of WeakReduce holds. For E = L9 − 1 = n'(P9 + 1) + m', with L9 = n(P9 + 1) + m: if m ≥ 1, then n' = n and m' = m − 1, so q = n leaves what it leaves there, and q = n − 1, only for m' < 36, at most (P9 + n + m + 1)·2^234 ≤ (P9 + 81)·2^234; if m = 0, then q = n − 1, as m' = P9 is not below 36, and leaves at most (P9 + n + 1)·2^234. The result is below 1.0001p either way, and as q is at most that of L9, q·p is at most the value. A limb of F below 2^28.9 with 2^32 − 2^6 − q·p_j above 2^31 keeps each limb of the chain positive and below 2^33.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompleteCyclotomic(Vector512<ulong> s0, Vector512<ulong> s1, Vector512<ulong> s2, Vector512<ulong> s3, Vector512<ulong> s4, Vector512<ulong> s5, Vector512<ulong> s6, Vector512<ulong> s7, Vector512<ulong> s8, Vector512<ulong> s9, ref ulong a, ref ulong result)
	{
		Carry(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref s8, ref s9);
		ReadOnlySpan<ulong> threeP = ThreeP;
		Vector512<ulong> even = Vector512.LoadUnsafe(in EvenLanes[0]);
		Vector512<ulong> f0 = FinishCyclotomicLimb(s0, in a, threeP[0], even);
		Vector512<ulong> f1 = FinishCyclotomicLimb(s1, in Unsafe.Add(ref a, 8), threeP[1], even);
		Vector512<ulong> f2 = FinishCyclotomicLimb(s2, in Unsafe.Add(ref a, 16), threeP[2], even);
		Vector512<ulong> f3 = FinishCyclotomicLimb(s3, in Unsafe.Add(ref a, 24), threeP[3], even);
		Vector512<ulong> f4 = FinishCyclotomicLimb(s4, in Unsafe.Add(ref a, 32), threeP[4], even);
		Vector512<ulong> f5 = FinishCyclotomicLimb(s5, in Unsafe.Add(ref a, 40), threeP[5], even);
		Vector512<ulong> f6 = FinishCyclotomicLimb(s6, in Unsafe.Add(ref a, 48), threeP[6], even);
		Vector512<ulong> f7 = FinishCyclotomicLimb(s7, in Unsafe.Add(ref a, 56), threeP[7], even);
		Vector512<ulong> f8 = FinishCyclotomicLimb(s8, in Unsafe.Add(ref a, 64), threeP[8], even);
		Vector512<ulong> f9 = FinishCyclotomicLimb(s9, in Unsafe.Add(ref a, 72), threeP[9], even);
		WeakReduce(f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, MultiplyLimb(f9 + (f8 >>> 26), QuotientMultiplier) >>> 40, ref result);
	}

	// Carry on AVX-512 itself.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ref Vector512<ulong> t0, ref Vector512<ulong> t1, ref Vector512<ulong> t2, ref Vector512<ulong> t3, ref Vector512<ulong> t4, ref Vector512<ulong> t5, ref Vector512<ulong> t6, ref Vector512<ulong> t7, ref Vector512<ulong> t8, ref Vector512<ulong> t9)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		t1 += (t0.AsInt64() >> 26).AsUInt64();
		t0 &= mask;
		t2 += (t1.AsInt64() >> 26).AsUInt64();
		t1 &= mask;
		t3 += (t2.AsInt64() >> 26).AsUInt64();
		t2 &= mask;
		t4 += (t3.AsInt64() >> 26).AsUInt64();
		t3 &= mask;
		t5 += (t4.AsInt64() >> 26).AsUInt64();
		t4 &= mask;
		t6 += (t5.AsInt64() >> 26).AsUInt64();
		t5 &= mask;
		t7 += (t6.AsInt64() >> 26).AsUInt64();
		t6 &= mask;
		t8 += (t7.AsInt64() >> 26).AsUInt64();
		t7 &= mask;
		t9 += (t8.AsInt64() >> 26).AsUInt64();
		t8 &= mask;
	}

	// The subtraction of q·p of WeakReduce and its store into result on AVX-512 itself, for limbs 0 to 8 in [0, 2^28.9) and a q that leaves the result in [0, 1.0001p): each limb takes 2^32 and gives 2^6 to the one above, which keeps every limb below the top one positive and below 2^33 while the value stays, and the chain carries the limbs as it goes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WeakReduce(Vector512<ulong> t0, Vector512<ulong> t1, Vector512<ulong> t2, Vector512<ulong> t3, Vector512<ulong> t4, Vector512<ulong> t5, Vector512<ulong> t6, Vector512<ulong> t7, Vector512<ulong> t8, Vector512<ulong> t9, Vector512<ulong> q, ref ulong result)
	{
		Vector512<ulong> mask = Vector512.Create(Mask);
		Vector512<ulong> borrow = Vector512.Create((1UL << 32) - (1UL << 6));
		t0 = t0 + Vector512.Create(1UL << 32) - MultiplyLimb(q, P0);
		t1 = t1 + borrow - MultiplyLimb(q, P1) + (t0 >>> 26);
		t2 = t2 + borrow - MultiplyLimb(q, P2) + (t1 >>> 26);
		t3 = t3 + borrow - MultiplyLimb(q, P3) + (t2 >>> 26);
		t4 = t4 + borrow - MultiplyLimb(q, P4) + (t3 >>> 26);
		t5 = t5 + borrow - MultiplyLimb(q, P5) + (t4 >>> 26);
		t6 = t6 + borrow - MultiplyLimb(q, P6) + (t5 >>> 26);
		t7 = t7 + borrow - MultiplyLimb(q, P7) + (t6 >>> 26);
		t8 = t8 + borrow - MultiplyLimb(q, P8) + (t7 >>> 26);
		t9 = t9 - Vector512.Create(1UL << 6) - MultiplyLimb(q, P9) + (t8 >>> 26);
		(t0 & mask).StoreUnsafe(ref result);
		(t1 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 8));
		(t2 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 16));
		(t3 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 24));
		(t4 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 32));
		(t5 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 40));
		(t6 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 48));
		(t7 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 56));
		(t8 & mask).StoreUnsafe(ref Unsafe.Add(ref result, 64));
		t9.StoreUnsafe(ref Unsafe.Add(ref result, 72));
	}

	// 3s + 2(cover − x) where even is set and 3s + 2x elsewhere, for one limb of CompleteCyclotomic.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> FinishCyclotomicLimb(Vector512<ulong> s, ref readonly ulong x, ulong cover, Vector512<ulong> even)
	{
		Vector512<ulong> value = Vector512.LoadUnsafe(in x);
		return s + (s << 1) + (Vector512.ConditionalSelect(even, Vector512.Create(cover) - value, value) << 1);
	}

	// The products of the lanes of x, below 2^32, by factor, as vpmuludq takes them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> MultiplyLimb(Vector512<ulong> x, uint factor)
	{
		return Avx512F.Multiply(x.AsUInt32(), Vector512.Create((ulong)factor).AsUInt32());
	}

	// The operands of the lane products of the cyclotomic square into six sets of ten rows: L = (X0, X0 + X1) and R = (X1, X0 + u·X1) on lanes 0 to 2 and 3 to 5 for their real parts, u-parts and sums, with u·X1 = 2(3p − x1) + x0·u. rotated takes value rotated by three lanes.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void PrepareCyclotomic(ref ulong a, ref ulong operands, ref ulong rotated)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		if (TVector.Count == RowLength)
		{
			TVector high = TVector.Load(in HighLanes[0]);

			for (int l = 0; l < LimbCount; ++l)
			{
				int row = RowLength * l;
				TVector cover = TVector.Create(threeP[l]);
				TVector x0 = TVector.Load(in Unsafe.Add(ref a, row));
				TVector x1 = TVector.Load(in Unsafe.Add(ref a, ComponentLength + row));
				TVector s0 = TVector.Permute(x0, x0, RotateThree);
				TVector s1 = TVector.Permute(x1, x1, RotateThree);
				TVector l0 = x0 + (s0 & high);
				TVector l1 = x1 + (s1 & high);
				TVector r0 = s0 + (cover - x1 << 1 & high);
				TVector r1 = s1 + (x0 & high);
				l0.Store(ref Unsafe.Add(ref operands, row));
				l1.Store(ref Unsafe.Add(ref operands, ComponentLength + row));
				(l0 + l1).Store(ref Unsafe.Add(ref operands, 2 * ComponentLength + row));
				r0.Store(ref Unsafe.Add(ref operands, 3 * ComponentLength + row));
				r1.Store(ref Unsafe.Add(ref operands, 4 * ComponentLength + row));
				(r0 + r1).Store(ref Unsafe.Add(ref operands, 5 * ComponentLength + row));
			}

			return;
		}

		for (int l = 0; l < 2 * LimbCount; ++l)
		{
			TVector.Permute(in Unsafe.Add(ref a, RowLength * l), in Unsafe.Add(ref a, RowLength * l), ref Unsafe.Add(ref rotated, RowLength * l), RotateThree);
		}

		for (int l = 0; l < LimbCount; ++l)
		{
			TVector cover = TVector.Create(threeP[l]);

			for (int i = 0; i < RowLength; i += TVector.Count)
			{
				int row = RowLength * l + i;
				TVector high = TVector.Load(in HighLanes[i]);
				TVector x0 = TVector.Load(in Unsafe.Add(ref a, row));
				TVector x1 = TVector.Load(in Unsafe.Add(ref a, ComponentLength + row));
				TVector s0 = TVector.Load(in Unsafe.Add(ref rotated, row));
				TVector s1 = TVector.Load(in Unsafe.Add(ref rotated, ComponentLength + row));
				TVector l0 = x0 + (s0 & high);
				TVector l1 = x1 + (s1 & high);
				TVector r0 = s0 + (cover - x1 << 1 & high);
				TVector r1 = s1 + (x0 & high);
				l0.Store(ref Unsafe.Add(ref operands, row));
				l1.Store(ref Unsafe.Add(ref operands, ComponentLength + row));
				(l0 + l1).Store(ref Unsafe.Add(ref operands, 2 * ComponentLength + row));
				r0.Store(ref Unsafe.Add(ref operands, 3 * ComponentLength + row));
				r1.Store(ref Unsafe.Add(ref operands, 4 * ComponentLength + row));
				(r0 + r1).Store(ref Unsafe.Add(ref operands, 5 * ComponentLength + row));
			}
		}
	}

	// For vectors narrower than a row, whose permutations go through memory: from the reduced m and n of the cyclotomic square, in lanes 0 to 2 and 3 to 5 of square, T as CombineCyclotomic forms it on the columns, here on the ten rows of each component, 3p covering each subtrahend, and then F = 3T + 2(3p − a) on the even lanes and 3T + 2a on the odd ones. From m and n below 1.0001p in limbs below 2^26, T is below 12p in limbs below 2^29 and F below 40.5p in limbs below 2^31.1, which WeakReduceElement takes. permuted holds four rows; a is read before result is written, row by row.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineCyclotomicRows(ref ulong square, ref ulong a, ref ulong result, ref ulong permuted)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		for (int l = 0; l < LimbCount; ++l)
		{
			int row = RowLength * l;
			ref ulong real = ref Unsafe.Add(ref square, row);
			ref ulong imaginary = ref Unsafe.Add(ref square, ComponentLength + row);
			TVector.Permute(in real, in imaginary, ref permuted, PermuteReal);
			TVector.Permute(in real, in imaginary, ref Unsafe.Add(ref permuted, RowLength), PermuteImaginary);
			TVector.Permute(in real, in real, ref Unsafe.Add(ref permuted, 2 * RowLength), SpreadEven);
			TVector.Permute(in imaginary, in imaginary, ref Unsafe.Add(ref permuted, 3 * RowLength), SpreadEven);
			TVector cover = TVector.Create(threeP[l]);

			for (int i = 0; i < RowLength; i += TVector.Count)
			{
				TVector even = TVector.Load(in EvenLanes[i]);
				TVector ar = TVector.Load(in Unsafe.Add(ref permuted, i));
				TVector ai = TVector.Load(in Unsafe.Add(ref permuted, RowLength + i));
				TVector br = TVector.Load(in Unsafe.Add(ref permuted, 2 * RowLength + i));
				TVector bi = TVector.Load(in Unsafe.Add(ref permuted, 3 * RowLength + i));
				TVector tr = TVector.ConditionalSelect(even, ar + (bi << 1) + cover - br, TVector.ConditionalSelect(TVector.Load(in LaneOne[i]), cover - ar << 2, ar << 1));
				TVector ti = TVector.ConditionalSelect(even, ai + (cover << 1) - br - bi, ai << 1);
				TVector xr = TVector.Load(in Unsafe.Add(ref a, row + i));
				TVector xi = TVector.Load(in Unsafe.Add(ref a, ComponentLength + row + i));
				(tr + (tr << 1) + (TVector.ConditionalSelect(even, cover - xr, xr) << 1)).Store(ref Unsafe.Add(ref result, row + i));
				(ti + (ti << 1) + (TVector.ConditionalSelect(even, cover - xi, xi) << 1)).Store(ref Unsafe.Add(ref result, ComponentLength + row + i));
			}
		}
	}

	// From the products of the cyclotomic square, for vectors of a whole row, which permute in registers: the lanes W = (P0 − 2P1) + (Ps − P0 − P1)·u, then T = A − (1 + u)·B + 64p² in each column, with A the permutation of W that the square takes and B = (W0, ·, W1, ·, W2, ·) on the even lanes: on the odd lanes T is 2A, whose lane 1, A_1 = (W2.u, W2.real), takes the factor u as (−2·W2.u, W2.real).
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineCyclotomic(ref ulong products, ref ulong combined)
	{
		Debug.Assert(TVector.Count == RowLength);

		ref ulong x0 = ref products;
		ref ulong x1 = ref Unsafe.Add(ref x0, WideLength);
		ref ulong xs = ref Unsafe.Add(ref x0, 2 * WideLength);
		ReadOnlySpan<ulong> offset = Offset;
		TVector even = TVector.Load(in EvenLanes[0]);
		TVector odd = TVector.Load(in OddLanes[0]);
		TVector one = TVector.Load(in LaneOne[0]);

		for (int s = 0; s < WideRows - 1; ++s)
		{
			int row = RowLength * s;
			TVector p0 = TVector.Load(in Unsafe.Add(ref x0, row));
			TVector p1 = TVector.Load(in Unsafe.Add(ref x1, row));
			TVector ps = TVector.Load(in Unsafe.Add(ref xs, row));
			TVector w0 = p0 - (p1 << 1);
			TVector w1 = ps - p0 - p1;
			TVector ar = TVector.Permute(w0, w1, PermuteReal);
			TVector ai = TVector.Permute(w0, w1, PermuteImaginary);
			TVector br = TVector.Permute(w0, w0, SpreadEven);
			TVector bi = TVector.Permute(w1, w1, SpreadEven);
			TVector off = TVector.Create(offset[s]);
			TVector dr = ar + (ar & odd);
			TVector tr = dr - (even & br - (bi << 1)) - (one & dr + (dr << 1));
			TVector ti = ai + (ai & odd) - (even & br + bi);
			(tr + off).Store(ref Unsafe.Add(ref combined, row));
			(ti + off).Store(ref Unsafe.Add(ref combined, WideLength + row));
		}

		TVector top = TVector.Create(offset[WideRows - 1]);
		top.Store(ref Unsafe.Add(ref combined, RowLength * (WideRows - 1)));
		top.Store(ref Unsafe.Add(ref combined, WideLength + RowLength * (WideRows - 1)));
	}

	internal static void Frobenius(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Scale(ref value[0], Frobenius1, true, ref result[0], ref scratch[0]);
	}

	internal static void FrobeniusSquared(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Scale(ref value[0], Frobenius2, false, ref result[0], ref scratch[0]);
	}

	internal static void FrobeniusCubed(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		Scale(ref value[0], Frobenius3, true, ref result[0], ref scratch[0]);
	}

	// Each coefficient, conjugated as x0 + (3p − x1)·u where conjugate is set, times the factor of its lane: products below 3p², which Reduce2 takes to below 1.0001p.
	[SkipLocalsInit]
	private static void Scale(ref ulong value, ReadOnlySpan<ulong> factors, bool conjugate, ref ulong result, ref ulong work)
	{
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong operand = ref Unsafe.Add(ref work, Operands);
		ref ulong gamma = ref MemoryMarshal.GetReference(factors);
		ref ulong imaginary = ref Unsafe.Add(ref value, ComponentLength);

		if (conjugate)
		{
			Negate(ref imaginary, ref operand);
			imaginary = ref operand;
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			AccumulateLanes(ref value, ref gamma, v, ref products);
			AccumulateLanes(ref imaginary, ref gamma, v, ref Unsafe.Add(ref products, WideLength));
		}

		ClearTopColumns(ref products);
		ClearTopColumns(ref Unsafe.Add(ref products, WideLength));

		for (int v = 0; v < VectorCount; ++v)
		{
			Reduce2(ref Unsafe.Add(ref products, v * TVector.Count), ref Unsafe.Add(ref products, WideLength + v * TVector.Count), ref Unsafe.Add(ref result, v * TVector.Count), ref Unsafe.Add(ref result, ComponentLength + v * TVector.Count));
		}
	}

	// 3p − x for the ten rows of a reduced x: limbs below 2^27 and a value below 3p.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Negate(ref ulong rows, ref ulong result)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;

		for (int l = 0; l < LimbCount; ++l)
		{
			TVector cover = TVector.Create(threeP[l]);

			for (int i = 0; i < RowLength; i += TVector.Count)
			{
				int row = RowLength * l + i;
				(cover - TVector.Load(in Unsafe.Add(ref rows, row))).Store(ref Unsafe.Add(ref result, row));
			}
		}
	}

	// Column 19 of a lane product, which AccumulateLanes leaves out, is 0.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ClearTopColumns(ref ulong wide)
	{
		for (int i = 0; i < RowLength; i += TVector.Count)
		{
			TVector.Zero.Store(ref Unsafe.Add(ref wide, RowLength * (WideRows - 1) + i));
		}
	}

	// value^(p⁶), the inverse in the cyclotomic subgroup: the odd lanes negated as 3p − x, reduced, where mask is set, and value as it is elsewhere.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void Conjugate(ulong mask, ref SM9Fp12Lanes value, ref SM9Fp12Lanes result)
	{
		ref ulong x = ref value[0];
		ref ulong r = ref result[0];
		ReadOnlySpan<ulong> threeP = ThreeP;
		TVector select = TVector.Create(mask);

		for (int c = 0; c < 2 * ComponentLength; c += ComponentLength)
		{
			for (int m = 0; m < LimbCount; ++m)
			{
				TVector cover = TVector.Create(threeP[m]);

				for (int i = 0; i < RowLength; i += TVector.Count)
				{
					int row = c + RowLength * m + i;
					TVector odd = TVector.Load(in OddLanes[i]) & select;
					TVector y = TVector.Load(in Unsafe.Add(ref x, row));
					TVector.ConditionalSelect(odd, cover - y, y).Store(ref Unsafe.Add(ref r, row));
				}
			}
		}

		WeakReduceElement(ref r);
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	internal static void ConditionalSelect(ulong mask, ref SM9Fp12Lanes whenSet, ref SM9Fp12Lanes whenClear, ref SM9Fp12Lanes result)
	{
		TVector select = TVector.Create(mask);
		ref ulong x = ref whenSet[0];
		ref ulong y = ref whenClear[0];
		ref ulong r = ref result[0];

		for (int i = 0; i < SM9Fp12Lanes.Length; i += TVector.Count)
		{
			TVector.ConditionalSelect(select, TVector.Load(in Unsafe.Add(ref x, i)), TVector.Load(in Unsafe.Add(ref y, i))).Store(ref Unsafe.Add(ref r, i));
		}
	}

	// The point (X : Y : Z) of the twist in lanes 0, 1 and 2, for the doubling step; its coefficients must be reduced.
	internal static void FromPoint(in SM9Point<SM9Fp2> point, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref rows), 0, SM9Fp12Lanes.Length * sizeof(ulong));
		Split(in point.X, ref rows, 0);
		Split(in point.Y, ref rows, 1);
		Split(in point.Z, ref rows, 2);
	}

	internal static void ToPoint(ref SM9Fp12Lanes value, out SM9Point<SM9Fp2> result)
	{
		ref ulong rows = ref value[0];
		Unsafe.SkipInit(out result);
		Join(ref rows, 0, out result.X);
		Join(ref rows, 1, out result.Y);
		Join(ref rows, 2, out result.Z);
	}

	// The factors of the line at P that the doubling step takes, −xP and yP, in the real parts of lanes 4 and 5 and 0 elsewhere.
	internal static void FromFactors(in SM9Fp negatedX, in SM9Fp y, ref SM9Fp12Lanes result)
	{
		ref ulong rows = ref result[0];
		Unsafe.InitBlockUnaligned(ref Unsafe.As<ulong, byte>(ref rows), 0, SM9Fp12Lanes.Length * sizeof(ulong));
		Split(in negatedX, ref Unsafe.Add(ref rows, 4));
		Split(in y, ref Unsafe.Add(ref rows, 5));
	}

	// For vectors of a whole row, T = 2T on the point in lanes 0 to 2, and the line of SM9MillerLoop's doubling step at P into lanes 0, 2 and 3 of line: l0 = B − E, below 4.0001p with limbs below 2^27.6, which MultiplyByLine takes, and l2 = 3X²·(−xP) and l3 = 2YZ·yP, reduced. The other lanes of line are 0, and those of point are left with values of no meaning.
	// The first products, of reduced inputs, are A = XY, B = Y², 3uC = 3Z·uZ, 3X² = X·3X and 2YZ = Y·2Z, whose operands are below 6.75p with limbs below 2^28: their values lie within (−31p², 56p²) and their columns below 2^60.2 in magnitude. 5·3uC is E = 3b'·C for b' = 5u, reduced once more. The second products are 2A·(B + 9p − 3E), (B + 3E)², 4B·2YZ, E², 3X²·(−xP) and 2YZ·yP, of operands below 10.0001p with limbs below 2^29 and sums below 2^29.3, and Y3 takes (B + F)² − 12E² before the reduction: their values lie within (−44p², 40p²) and their columns below 2^62.1 in magnitude, which the reduction takes.
	[SkipLocalsInit]
	internal static void DoublingStep(ref SM9Fp12Lanes point, ref SM9Fp12Lanes factors, ref SM9Fp12Lanes line, ref SM9LaneScratch scratch)
	{
		ref ulong t = ref point[0];
		ref ulong work = ref scratch[0];
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong operands = ref Unsafe.Add(ref work, Operands);
		ref ulong level = ref Unsafe.Add(ref work, Temporary);
		ref ulong combined = ref Unsafe.Add(ref work, Combined);
		ref ulong lineRows = ref Unsafe.Add(ref work, LineRows);
		Debug.Assert(TVector.Count == RowLength && LineRows + 2 * ComponentLength == SM9LaneScratch.Length);
		PrepareDoubling(ref t, ref operands);
		AccumulateOperands(ref operands, ref products);

		for (int v = 0; v < VectorCount; ++v)
		{
			ReduceProducts(ref products, v, ref level);
		}

		ScaleLanes(ref level, LevelScale);
		WeakReduceRows(ref level);
		WeakReduceRows(ref Unsafe.Add(ref level, ComponentLength));
		PrepareSecondDoubling(ref level, ref factors[0], ref operands, ref lineRows);
		AccumulateOperands(ref operands, ref products);
		CombineSecondDoubling(ref products, ref combined);

		for (int v = 0; v < VectorCount; ++v)
		{
			Reduce2(ref Unsafe.Add(ref combined, v * TVector.Count), ref Unsafe.Add(ref combined, WideLength + v * TVector.Count), ref Unsafe.Add(ref t, v * TVector.Count), ref Unsafe.Add(ref t, ComponentLength + v * TVector.Count));
		}

		AssembleLine(ref lineRows, ref t, ref line[0]);
	}

	// The three Karatsuba products of the six sets of operands, for every vector.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateOperands(ref ulong operands, ref ulong products)
	{
		for (int v = 0; v < VectorCount; ++v)
		{
			AccumulateLanes(ref operands, ref Unsafe.Add(ref operands, 3 * ComponentLength), v, ref products);
			AccumulateLanes(ref Unsafe.Add(ref operands, ComponentLength), ref Unsafe.Add(ref operands, 4 * ComponentLength), v, ref Unsafe.Add(ref products, WideLength));
			AccumulateLanes(ref Unsafe.Add(ref operands, 2 * ComponentLength), ref Unsafe.Add(ref operands, 5 * ComponentLength), v, ref Unsafe.Add(ref products, 2 * WideLength));
		}
	}

	// The operands of the first products, (X, Y, 3Z, X, Y) by (Y, Y, uZ, 3X, 2Z), uZ = 2(3p − z1) + z0·u, with their sums.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void PrepareDoubling(ref ulong t, ref ulong operands)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;
		TVector leftScale = TVector.Load(in DoublingLeftScale[0]);
		TVector rightScale = TVector.Load(in DoublingRightScale[0]);
		TVector two = TVector.Load(in LaneTwo[0]);

		for (int l = 0; l < LimbCount; ++l)
		{
			int row = RowLength * l;
			TVector cover = TVector.Create(threeP[l]);
			TVector t0 = TVector.Load(in Unsafe.Add(ref t, row));
			TVector t1 = TVector.Load(in Unsafe.Add(ref t, ComponentLength + row));
			TVector l0 = TVector.Multiply(TVector.Permute(t0, t0, DoublingLeft), leftScale);
			TVector l1 = TVector.Multiply(TVector.Permute(t1, t1, DoublingLeft), leftScale);
			TVector r0 = TVector.Permute(t0, t1, DoublingRight);
			r0 = TVector.Multiply(TVector.ConditionalSelect(two, cover - r0 << 1, r0), rightScale);
			TVector r1 = TVector.Multiply(TVector.Permute(t1, t0, DoublingRight), rightScale);
			l0.Store(ref Unsafe.Add(ref operands, row));
			l1.Store(ref Unsafe.Add(ref operands, ComponentLength + row));
			(l0 + l1).Store(ref Unsafe.Add(ref operands, 2 * ComponentLength + row));
			r0.Store(ref Unsafe.Add(ref operands, 3 * ComponentLength + row));
			r1.Store(ref Unsafe.Add(ref operands, 4 * ComponentLength + row));
			(r0 + r1).Store(ref Unsafe.Add(ref operands, 5 * ComponentLength + row));
		}
	}

	// Each row of the twenty at rows times the lane factors of scale.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ScaleLanes(ref ulong rows, ReadOnlySpan<ulong> scale)
	{
		for (int l = 0; l < 2 * LimbCount; ++l)
		{
			for (int i = 0; i < RowLength; i += TVector.Count)
			{
				ref ulong x = ref Unsafe.Add(ref rows, RowLength * l + i);
				TVector.Multiply(TVector.Load(in x), TVector.Load(in scale[i])).Store(ref x);
			}
		}
	}

	// From (A, B, E, 3X², 2YZ), the operands of the second products, (2A, B + 3E, 4B, E, 3X², 2YZ) by (B + 9p − 3E, B + 3E, 2YZ, E, −xP, yP), and l0 = B + 3p − E in lane 0 of lineRows.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void PrepareSecondDoubling(ref ulong level, ref ulong factors, ref ulong operands, ref ulong lineRows)
	{
		ReadOnlySpan<ulong> threeP = ThreeP;
		ReadOnlySpan<ulong> nineP = NineP;
		TVector scale = TVector.Load(in SecondLeftScale[0]);
		TVector one = TVector.Load(in LaneOne[0]);
		TVector zero = TVector.Load(in LaneZero[0]);
		TVector factorLanes = TVector.Load(in FactorLanes[0]);

		for (int c = 0; c < 2; ++c)
		{
			for (int l = 0; l < LimbCount; ++l)
			{
				int row = ComponentLength * c + RowLength * l;
				TVector x = TVector.Load(in Unsafe.Add(ref level, row));
				TVector g = TVector.Permute(x, x, SecondLeft);
				TVector e = TVector.Permute(x, x, SpreadE);
				TVector b = TVector.Permute(x, x, SecondRight);
				TVector f = e + (e << 1);
				TVector left = TVector.Multiply(g, scale) + (f & one);
				TVector right = b + (TVector.Create(nineP[l]) - f & zero) + (f & one);
				right = TVector.ConditionalSelect(factorLanes, TVector.Load(in Unsafe.Add(ref factors, row)), right);
				left.Store(ref Unsafe.Add(ref operands, row));
				right.Store(ref Unsafe.Add(ref operands, 3 * ComponentLength + row));
				(b + TVector.Create(threeP[l]) - e).Store(ref Unsafe.Add(ref lineRows, row));
			}
		}

		AddSums(ref operands);
	}

	// The Karatsuba sums of the six sets of operands: set 2 is set 0 plus set 1, and set 5 is set 3 plus set 4.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddSums(ref ulong operands)
	{
		for (int i = 0; i < ComponentLength; i += TVector.Count)
		{
			(TVector.Load(in Unsafe.Add(ref operands, i)) + TVector.Load(in Unsafe.Add(ref operands, ComponentLength + i))).Store(ref Unsafe.Add(ref operands, 2 * ComponentLength + i));
			(TVector.Load(in Unsafe.Add(ref operands, 3 * ComponentLength + i)) + TVector.Load(in Unsafe.Add(ref operands, 4 * ComponentLength + i))).Store(ref Unsafe.Add(ref operands, 5 * ComponentLength + i));
		}
	}

	// The products of Fp2 of the second doubling products, then Y3 = (B + 3E)² − 12E² in lane 1 from lanes 1 and 3, and 64p² added.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineSecondDoubling(ref ulong products, ref ulong combined)
	{
		ref ulong x0 = ref products;
		ref ulong x1 = ref Unsafe.Add(ref x0, WideLength);
		ref ulong xs = ref Unsafe.Add(ref x0, 2 * WideLength);
		ReadOnlySpan<ulong> offset = Offset;
		TVector one = TVector.Load(in LaneOne[0]);

		for (int s = 0; s < WideRows - 1; ++s)
		{
			int row = RowLength * s;
			TVector p0 = TVector.Load(in Unsafe.Add(ref x0, row));
			TVector p1 = TVector.Load(in Unsafe.Add(ref x1, row));
			TVector ps = TVector.Load(in Unsafe.Add(ref xs, row));
			TVector w0 = p0 - (p1 << 1);
			TVector w1 = ps - p0 - p1;
			TVector e0 = TVector.Permute(w0, w0, LaneThreeToOne);
			TVector e1 = TVector.Permute(w1, w1, LaneThreeToOne);
			TVector off = TVector.Create(offset[s]);
			(w0 - ((e0 << 3) + (e0 << 2) & one) + off).Store(ref Unsafe.Add(ref combined, row));
			(w1 - ((e1 << 3) + (e1 << 2) & one) + off).Store(ref Unsafe.Add(ref combined, WideLength + row));
		}

		TVector top = TVector.Create(offset[WideRows - 1]);
		top.Store(ref Unsafe.Add(ref combined, RowLength * (WideRows - 1)));
		top.Store(ref Unsafe.Add(ref combined, WideLength + RowLength * (WideRows - 1)));
	}

	// The line (l0, l2, l3) into lanes 0, 2 and 3 from lane 0 of lineRows and lanes 4 and 5 of the reduced second products.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AssembleLine(ref ulong lineRows, ref ulong reduced, ref ulong line)
	{
		TVector lanes = TVector.Load(in LineLanes[0]);

		for (int l = 0; l < 2 * LimbCount; ++l)
		{
			int row = RowLength * l;
			(TVector.Permute(TVector.Load(in Unsafe.Add(ref lineRows, row)), TVector.Load(in Unsafe.Add(ref reduced, row)), AssembleLinePattern) & lanes).Store(ref Unsafe.Add(ref line, row));
		}
	}

	// The element of value weakly reduced, from limbs below 2^62 and values below 2^261.
	internal static void WeakReduce(ref SM9Fp12Lanes value)
	{
		WeakReduceElement(ref value[0]);
	}

	// As AccumulateWide for sixteen registers, with right, wide and middle at the qword of the vector: by the same halves, each term takes three products of 25 lane products into nine columns, one at a time with nine sums, five limbs of y and one of x in registers: L into columns 0 to 8, H into 10 to 18 and M into the nine rows at middle, which CombineHalves then adds in. L and H share one copy of Block, so that the copies stay within the budget of the inliner.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AccumulateNarrow(ref ulong left, ref ulong right, ulong terms, ulong sources, int termCount, ref ulong wide, ref ulong middle)
	{
		ClearRows(ref wide, WideRows - 1);
		ClearRows(ref middle, 2 * HalfLimbs - 1);

		for (int t = 0; t < termCount; ++t)
		{
			int i = (int)(terms >> 4 * t) & 15;
			ref ulong x = ref Unsafe.Add(ref left, Source(sources, t));
			ref ulong y = ref Unsafe.Add(ref right, ExtendedOrigin - i);

			for (int h = 0; h < 2 * HalfLimbs; h += HalfLimbs)
			{
				Block(ref Unsafe.Add(ref x, RowLength * h), Broadcast, ref Unsafe.Add(ref y, ExtendedRowLength * h), ExtendedRowLength, ref Unsafe.Add(ref wide, 2 * RowLength * h));
			}

			Block(ref x, BroadcastSum, ref Unsafe.Add(ref y, ExtendedRowLength * LimbCount), ExtendedRowLength, ref middle);
		}

		CombineHalves(ref wide, ref middle);
	}

	// As AccumulateWide for sixteen registers with whole operands, for the terms too few to pay for the sums of the halves: each operand in two halves of five limbs, whose four products take 25 lane products into nine of the columns, one at a time with nine sums, five limbs of y and one of x in registers.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AccumulateNarrowWhole(ref ulong left, ref ulong right, ulong terms, ulong sources, int termCount, int v, ref ulong wide)
	{
		wide = ref Unsafe.Add(ref wide, v * TVector.Count);
		ClearRows(ref wide, WideRows - 1);

		for (int t = 0; t < termCount; ++t)
		{
			int i = (int)(terms >> 4 * t) & 15;
			ref ulong x = ref Unsafe.Add(ref left, Source(sources, t));
			ref ulong y = ref Unsafe.Add(ref right, ExtendedOrigin - i + v * TVector.Count);

			for (int h = 0; h < 4; ++h)
			{
				int hx = HalfLimbs * (h >> 1);
				int hy = HalfLimbs * (h & 1);
				Block(ref Unsafe.Add(ref x, RowLength * hx), Broadcast, ref Unsafe.Add(ref y, ExtendedRowLength * hy), ExtendedRowLength, ref Unsafe.Add(ref wide, RowLength * (hx + hy)));
			}
		}
	}

	// The rows of the whole products from those of AccumulateNarrow: M − L − H added to columns 5 to 13, column 9 being 0, all of them read before any is written.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineHalves(ref ulong wide, ref ulong middle)
	{
		TVector m0 = CrossColumn(ref wide, ref middle, 0);
		TVector m1 = CrossColumn(ref wide, ref middle, 1);
		TVector m2 = CrossColumn(ref wide, ref middle, 2);
		TVector m3 = CrossColumn(ref wide, ref middle, 3);
		TVector m4 = CrossColumn(ref wide, ref middle, 4);
		TVector m5 = CrossColumn(ref wide, ref middle, 5);
		TVector m6 = CrossColumn(ref wide, ref middle, 6);
		TVector m7 = CrossColumn(ref wide, ref middle, 7);
		TVector m8 = CrossColumn(ref wide, ref middle, 8);
		AddRow(ref wide, 5, m0);
		AddRow(ref wide, 6, m1);
		AddRow(ref wide, 7, m2);
		AddRow(ref wide, 8, m3);
		AddRow(ref wide, 9, m4);
		AddRow(ref wide, 10, m5);
		AddRow(ref wide, 11, m6);
		AddRow(ref wide, 12, m7);
		AddRow(ref wide, 13, m8);
	}

	// Column j of M − L − H.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector CrossColumn(ref ulong wide, ref ulong middle, int j)
	{
		return TVector.Load(in Unsafe.Add(ref middle, RowLength * j)) - TVector.Load(in Unsafe.Add(ref wide, RowLength * j)) - TVector.Load(in Unsafe.Add(ref wide, RowLength * (LimbCount + j)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddRow(ref ulong wide, int row, TVector value)
	{
		ref ulong target = ref Unsafe.Add(ref wide, RowLength * row);
		(TVector.Load(in target) + value).Store(ref target);
	}

	// As AccumulateLanesWide for sixteen registers.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void AccumulateLanesNarrow(ref ulong left, ref ulong right, int v, ref ulong wide)
	{
		wide = ref Unsafe.Add(ref wide, v * TVector.Count);
		ClearRows(ref wide, WideRows - 1);
		ref ulong x = ref Unsafe.Add(ref left, v * TVector.Count);
		ref ulong y = ref Unsafe.Add(ref right, v * TVector.Count);

		for (int h = 0; h < 4; ++h)
		{
			int hx = 5 * (h >> 1);
			int hy = 5 * (h & 1);
			Block(ref Unsafe.Add(ref x, RowLength * hx), Whole, ref Unsafe.Add(ref y, RowLength * hy), RowLength, ref Unsafe.Add(ref wide, RowLength * (hx + hy)));
		}
	}

	// The 25 products of five limbs of x, loaded as kind says, and five of y at stride yStride, added to the nine columns at wide.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Block(ref ulong x, int kind, ref ulong y, int yStride, ref ulong wide)
	{
		TVector y0 = TVector.Load(in y);
		TVector y1 = TVector.Load(in Unsafe.Add(ref y, yStride * 1));
		TVector y2 = TVector.Load(in Unsafe.Add(ref y, yStride * 2));
		TVector y3 = TVector.Load(in Unsafe.Add(ref y, yStride * 3));
		TVector y4 = TVector.Load(in Unsafe.Add(ref y, yStride * 4));
		TVector c0 = TVector.Load(in wide);
		TVector c1 = TVector.Load(in Unsafe.Add(ref wide, 8));
		TVector c2 = TVector.Load(in Unsafe.Add(ref wide, 16));
		TVector c3 = TVector.Load(in Unsafe.Add(ref wide, 24));
		TVector c4 = TVector.Load(in Unsafe.Add(ref wide, 32));
		TVector c5 = TVector.Load(in Unsafe.Add(ref wide, 40));
		TVector c6 = TVector.Load(in Unsafe.Add(ref wide, 48));
		TVector c7 = TVector.Load(in Unsafe.Add(ref wide, 56));
		TVector c8 = TVector.Load(in Unsafe.Add(ref wide, 64));
		TVector x0 = LoadOperand(kind, in x);
		c0 = TVector.MultiplyAdd(c0, x0, y0);
		c1 = TVector.MultiplyAdd(c1, x0, y1);
		c2 = TVector.MultiplyAdd(c2, x0, y2);
		c3 = TVector.MultiplyAdd(c3, x0, y3);
		c4 = TVector.MultiplyAdd(c4, x0, y4);
		TVector x1 = LoadOperand(kind, in Unsafe.Add(ref x, 8));
		c1 = TVector.MultiplyAdd(c1, x1, y0);
		c2 = TVector.MultiplyAdd(c2, x1, y1);
		c3 = TVector.MultiplyAdd(c3, x1, y2);
		c4 = TVector.MultiplyAdd(c4, x1, y3);
		c5 = TVector.MultiplyAdd(c5, x1, y4);
		TVector x2 = LoadOperand(kind, in Unsafe.Add(ref x, 16));
		c2 = TVector.MultiplyAdd(c2, x2, y0);
		c3 = TVector.MultiplyAdd(c3, x2, y1);
		c4 = TVector.MultiplyAdd(c4, x2, y2);
		c5 = TVector.MultiplyAdd(c5, x2, y3);
		c6 = TVector.MultiplyAdd(c6, x2, y4);
		TVector x3 = LoadOperand(kind, in Unsafe.Add(ref x, 24));
		c3 = TVector.MultiplyAdd(c3, x3, y0);
		c4 = TVector.MultiplyAdd(c4, x3, y1);
		c5 = TVector.MultiplyAdd(c5, x3, y2);
		c6 = TVector.MultiplyAdd(c6, x3, y3);
		c7 = TVector.MultiplyAdd(c7, x3, y4);
		TVector x4 = LoadOperand(kind, in Unsafe.Add(ref x, 32));
		c4 = TVector.MultiplyAdd(c4, x4, y0);
		c5 = TVector.MultiplyAdd(c5, x4, y1);
		c6 = TVector.MultiplyAdd(c6, x4, y2);
		c7 = TVector.MultiplyAdd(c7, x4, y3);
		c8 = TVector.MultiplyAdd(c8, x4, y4);
		c0.Store(ref wide);
		c1.Store(ref Unsafe.Add(ref wide, 8));
		c2.Store(ref Unsafe.Add(ref wide, 16));
		c3.Store(ref Unsafe.Add(ref wide, 24));
		c4.Store(ref Unsafe.Add(ref wide, 32));
		c5.Store(ref Unsafe.Add(ref wide, 40));
		c6.Store(ref Unsafe.Add(ref wide, 48));
		c7.Store(ref Unsafe.Add(ref wide, 56));
		c8.Store(ref Unsafe.Add(ref wide, 64));
	}

	// How Block loads x: whole vectors, one lane broadcast, or the sum of the lanes of rows m and m + 5 broadcast, for the halves of Karatsuba.
	private const int Whole = 0;

	private const int Broadcast = 1;

	private const int BroadcastSum = 2;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static TVector LoadOperand(int kind, ref readonly ulong source)
	{
		return kind switch
		{
			Broadcast => TVector.LoadBroadcast(in source),
			BroadcastSum => TVector.LoadBroadcast(in source) + TVector.LoadBroadcast(in Unsafe.Add(ref Unsafe.AsRef(in source), RowLength * HalfLimbs)),
			_ => TVector.Load(in source)
		};
	}

	// The first count rows of one vector at rows, which the narrow kernels add to.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ClearRows(ref ulong rows, int count)
	{
		for (int s = 0; s < count; ++s)
		{
			TVector.Zero.Store(ref Unsafe.Add(ref rows, RowLength * s));
		}
	}

	// As Reduce2 for one set of columns, for sixteen registers: the window of ten vectors and q stay in registers, the factors come from memory.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Reduce1(ref ulong columns, ref ulong result)
	{
		Load(ref columns, out TVector t0, out TVector t1, out TVector t2, out TVector t3, out TVector t4, out TVector t5, out TVector t6, out TVector t7, out TVector t8, out TVector t9);
		ref ulong next = ref Unsafe.Add(ref columns, 80);

		for (int k = 0; k < 10; ++k)
		{
			TVector q = TVector.MultiplyByFactor(t0, NegativeInverse) & TVector.Create(Mask);
			t0 = t1 + TVector.ShiftRightArithmetic26(t0 + TVector.Create(Mask)) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
			t1 = TVector.MultiplyAddByFactor(t2, q, P2);
			t2 = TVector.MultiplyAddByFactor(t3, q, P3);
			t3 = TVector.MultiplyAddByFactor(t4, q, P4);
			t4 = TVector.MultiplyAddByFactor(t5, q, P5);
			t5 = TVector.MultiplyAddByFactor(t6, q, P6);
			t6 = TVector.MultiplyAddByFactor(t7, q, P7);
			t7 = TVector.MultiplyAddByFactor(t8, q, P8);
			t8 = TVector.MultiplyAddByFactor(t9, q, P9);
			t9 = TVector.Load(in next);
			next = ref Unsafe.Add(ref next, 8);
		}

		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
	}

	// The lane products x·y of the ten rows of left and of right, as AccumulateLanes gives them, reduced as Reduce1 reduces them, for vector v: row k, limb k of y times every limb of x, adds to columns k to k + 9 alone, so column k is complete after it, and round k of the reduction, which adds to those columns too, follows it. A window of ten vectors holds columns k to k + 9, column k leaving it after round k and column k + 10 coming in at 0, and round k takes the column that Reduce1 takes in its round k, so the result is that of Reduce1, with the latency of the rounds overlapping the products. The limbs of x come from memory at each use, so the window, y_k, y_(k+1) and q fit in sixteen registers. Every addend of a column is a non-negative product or carry of Reduce1, so each partial column is at most the column there, and the carries shift logically.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void MultiplyReduceLanes(ref ulong left, ref ulong right, int v, ref ulong result)
	{
		ref ulong x = ref Unsafe.Add(ref left, v * TVector.Count);
		ref ulong y = ref Unsafe.Add(ref right, v * TVector.Count);
		TVector yk = TVector.Load(in y);
		TVector t0 = TVector.Multiply(TVector.Load(in x), yk);
		TVector t1 = TVector.Zero;
		TVector t2 = TVector.Zero;
		TVector t3 = TVector.Zero;
		TVector t4 = TVector.Zero;
		TVector t5 = TVector.Zero;
		TVector t6 = TVector.Zero;
		TVector t7 = TVector.Zero;
		TVector t8 = TVector.Zero;
		TVector q;

		// Column k is complete as round k starts: x0·y_(k+1), the product of row k + 1 in column k + 1, joins it with the terms that do not wait for q, as in Reduce1. Column k + 9 is 0 before row k, which gives it its first product.
		for (int k = 0; k < LimbCount - 1; ++k)
		{
			TVector next = TVector.Load(in Unsafe.Add(ref y, RowLength * (k + 1)));
			q = TVector.MultiplyByFactor(t0, NegativeInverse) & TVector.Create(Mask);
			t0 = TVector.MultiplyAdd(t1, TVector.Load(in Unsafe.Add(ref x, 8)), yk) + TVector.Multiply(TVector.Load(in x), next) + (t0 + TVector.Create(Mask) >>> 26) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
			t1 = TVector.MultiplyAdd(t2, TVector.Load(in Unsafe.Add(ref x, 16)), yk) + TVector.MultiplyByFactor(q, P2);
			t2 = TVector.MultiplyAdd(t3, TVector.Load(in Unsafe.Add(ref x, 24)), yk) + TVector.MultiplyByFactor(q, P3);
			t3 = TVector.MultiplyAdd(t4, TVector.Load(in Unsafe.Add(ref x, 32)), yk) + TVector.MultiplyByFactor(q, P4);
			t4 = TVector.MultiplyAdd(t5, TVector.Load(in Unsafe.Add(ref x, 40)), yk) + TVector.MultiplyByFactor(q, P5);
			t5 = TVector.MultiplyAdd(t6, TVector.Load(in Unsafe.Add(ref x, 48)), yk) + TVector.MultiplyByFactor(q, P6);
			t6 = TVector.MultiplyAdd(t7, TVector.Load(in Unsafe.Add(ref x, 56)), yk) + TVector.MultiplyByFactor(q, P7);
			t7 = TVector.MultiplyAdd(t8, TVector.Load(in Unsafe.Add(ref x, 64)), yk) + TVector.MultiplyByFactor(q, P8);
			t8 = TVector.Multiply(TVector.Load(in Unsafe.Add(ref x, 72)), yk) + TVector.MultiplyByFactor(q, P9);
			yk = next;
		}

		q = TVector.MultiplyByFactor(t0, NegativeInverse) & TVector.Create(Mask);
		t0 = TVector.MultiplyAdd(t1, TVector.Load(in Unsafe.Add(ref x, 8)), yk) + (t0 + TVector.Create(Mask) >>> 26) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
		t1 = TVector.MultiplyAdd(t2, TVector.Load(in Unsafe.Add(ref x, 16)), yk) + TVector.MultiplyByFactor(q, P2);
		t2 = TVector.MultiplyAdd(t3, TVector.Load(in Unsafe.Add(ref x, 24)), yk) + TVector.MultiplyByFactor(q, P3);
		t3 = TVector.MultiplyAdd(t4, TVector.Load(in Unsafe.Add(ref x, 32)), yk) + TVector.MultiplyByFactor(q, P4);
		t4 = TVector.MultiplyAdd(t5, TVector.Load(in Unsafe.Add(ref x, 40)), yk) + TVector.MultiplyByFactor(q, P5);
		t5 = TVector.MultiplyAdd(t6, TVector.Load(in Unsafe.Add(ref x, 48)), yk) + TVector.MultiplyByFactor(q, P6);
		t6 = TVector.MultiplyAdd(t7, TVector.Load(in Unsafe.Add(ref x, 56)), yk) + TVector.MultiplyByFactor(q, P7);
		t7 = TVector.MultiplyAdd(t8, TVector.Load(in Unsafe.Add(ref x, 64)), yk) + TVector.MultiplyByFactor(q, P8);
		t8 = TVector.Multiply(TVector.Load(in Unsafe.Add(ref x, 72)), yk) + TVector.MultiplyByFactor(q, P9);
		TVector mask = TVector.Create(Mask);
		t1 += t0 >>> 26;
		t2 += t1 >>> 26;
		t3 += t2 >>> 26;
		t4 += t3 >>> 26;
		t5 += t4 >>> 26;
		t6 += t5 >>> 26;
		t7 += t6 >>> 26;
		t8 += t7 >>> 26;
		WeakReduce(t0 & mask, t1 & mask, t2 & mask, t3 & mask, t4 & mask, t5 & mask, t6 & mask, t7 & mask, t8 & mask, t8 >>> 26, ref Unsafe.Add(ref result, v * TVector.Count));
	}

	// The square as Fp12 = Fp6[W]/(W² − v), v = W², with A0 = (a0, a2, a4) on the even lanes and A1 = (a1, a3, a5) on the odd ones: with t = A0·A1 and s = (A0 + A1)(A0 + v·A1), the square is (s − t − v·t) + 2t·W. The two products of Fp6 = Fp2[v]/(v³ − u) go side by side, t_m in lane 2m and s_m in lane 2m + 1: term i broadcasts the pair (A0_i, (A0 + A1)_i) and takes Y = (A1_n, (A0 + v·A1)_n) rotated by i pairs, so three terms take what six take in Multiply.
	// The pairs and Y, sums below 4.5p and 8.25p, are weakly reduced first, so every operand is below 1.0001p with limbs below 2^26, but u·Y below 6p with limbs below 2^28. Each term then adds to c0 a value in (−2.0004p², 6.0006p²) and to c1 one in [0, 7.0007p²), so the columns stay below 2^60.2 in magnitude, and s − t − v·t and 2t lie in (−42p², 66p²), 64p² added.
	// Vectors narrower than a row take the square as Multiply does, as their permutations would go through memory. The formula below is for vectors of a whole row, with 32 registers.
	[SkipLocalsInit]
	internal static void Square(ref SM9Fp12Lanes value, ref SM9Fp12Lanes result, ref SM9LaneScratch scratch)
	{
		if (TVector.Count < RowLength)
		{
			Product(ref value[0], ref value[0], AllTerms, AllSources, 6, ref result[0], ref scratch[0]);
			return;
		}

		ref ulong a = ref value[0];
		ref ulong work = ref scratch[0];
		ref ulong products = ref Unsafe.Add(ref work, Products);
		ref ulong extended = ref Unsafe.Add(ref work, Extended);
		ref ulong leftSums = ref Unsafe.Add(ref work, LeftSums);
		ref ulong pairs = ref Unsafe.Add(ref work, Temporary);
		ref ulong combined = ref Unsafe.Add(ref work, Combined);
		PrepareSquare(ref a, ref pairs, ref combined);
		WeakReduceElement(ref pairs);
		WeakReduceElement(ref combined);
		AddRows(ref pairs, ref Unsafe.Add(ref pairs, ComponentLength), ref leftSums);
		Extend(ref combined, ref extended, true);

		for (int v = 0; v < VectorCount; ++v)
		{
			AccumulateWide<PairBroadcast>(ref pairs, ref extended, EvenTerms, EvenSources, 3, v, ref products);
			AccumulateWide<PairBroadcast>(ref Unsafe.Add(ref pairs, ComponentLength), ref Unsafe.Add(ref extended, ExtendedLength), EvenTerms, EvenSources, 3, v, ref Unsafe.Add(ref products, WideLength));
			AccumulateWide<PairBroadcast>(ref leftSums, ref Unsafe.Add(ref extended, 2 * ExtendedLength), EvenTerms, EvenSources, 3, v, ref Unsafe.Add(ref products, 2 * WideLength));
		}

		CombineSquare(ref products, ref combined);

		for (int v = 0; v < VectorCount; ++v)
		{
			Reduce2(ref Unsafe.Add(ref combined, v * TVector.Count), ref Unsafe.Add(ref combined, WideLength + v * TVector.Count), ref Unsafe.Add(ref result[0], v * TVector.Count), ref Unsafe.Add(ref result[0], ComponentLength + v * TVector.Count));
		}
	}

	// The pairs (a_2m, a_2m + a_2m+1) and Y = (a_2m+1, a_2m + (v·A1)_m), (v·A1)_0 = u·a5 = 2(3p − a5') + a5·u, for each component and limb.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void PrepareSquare(ref ulong a, ref ulong pairs, ref ulong y)
	{
		Debug.Assert(TVector.Count == RowLength);

		ReadOnlySpan<ulong> threeP = ThreeP;
		TVector odd = TVector.Load(in OddLanes[0]);
		TVector one = TVector.Load(in LaneOne[0]);

		for (int l = 0; l < LimbCount; ++l)
		{
			int row = RowLength * l;
			TVector cover = TVector.Create(threeP[l]);
			TVector x0 = TVector.Load(in Unsafe.Add(ref a, row));
			TVector x1 = TVector.Load(in Unsafe.Add(ref a, ComponentLength + row));
			(x0 + (TVector.Permute(x0, x0, EvenToOdd) & odd)).Store(ref Unsafe.Add(ref pairs, row));
			(x1 + (TVector.Permute(x1, x1, EvenToOdd) & odd)).Store(ref Unsafe.Add(ref pairs, ComponentLength + row));
			TVector q0 = TVector.Permute(x0, x1, SquareSum);
			q0 = TVector.ConditionalSelect(one, cover - q0 << 1, q0);
			TVector q1 = TVector.Permute(x1, x0, SquareSum);
			(TVector.Permute(x0, x0, SwapPairs) + (q0 & odd)).Store(ref Unsafe.Add(ref y, row));
			(TVector.Permute(x1, x1, SwapPairs) + (q1 & odd)).Store(ref Unsafe.Add(ref y, ComponentLength + row));
		}
	}

	// From the products of the square, the lanes W = (P0 − 2P1) + (Ps − P0 − P1)·u, then s − t − v·t on the even lanes and 2t on the odd ones, 64p² added: s_m comes from lane 2m + 1 and t_m from lane 2m, and (v·t)_m is t_(m−1) from lane 2m − 2, or u·t_2 = −2·t_2' + t_2·u from lane 4 for m = 0.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void CombineSquare(ref ulong products, ref ulong combined)
	{
		ref ulong x0 = ref products;
		ref ulong x1 = ref Unsafe.Add(ref x0, WideLength);
		ref ulong xs = ref Unsafe.Add(ref x0, 2 * WideLength);
		ReadOnlySpan<ulong> offset = Offset;

		Debug.Assert(TVector.Count == RowLength);

		TVector even = TVector.Load(in EvenLanes[0]);
		TVector zero = TVector.Load(in LaneZero[0]);

		for (int s = 0; s < WideRows - 1; ++s)
		{
			int row = RowLength * s;
			TVector p0 = TVector.Load(in Unsafe.Add(ref x0, row));
			TVector p1 = TVector.Load(in Unsafe.Add(ref x1, row));
			TVector ps = TVector.Load(in Unsafe.Add(ref xs, row));
			TVector w0 = p0 - (p1 << 1);
			TVector w1 = ps - p0 - p1;
			TVector off = TVector.Create(offset[s]);
			TVector v0 = TVector.Permute(w0, w1, TimesV);
			TVector v1 = TVector.Permute(w1, w0, TimesV);
			TVector e0 = TVector.Permute(w0, w0, OddToEven) - w0 - v0 + (zero & v0 + (v0 << 1));
			TVector e1 = TVector.Permute(w1, w1, OddToEven) - w1 - v1;
			(TVector.ConditionalSelect(even, e0, TVector.Permute(w0, w0, EvenToOdd) << 1) + off).Store(ref Unsafe.Add(ref combined, row));
			(TVector.ConditionalSelect(even, e1, TVector.Permute(w1, w1, EvenToOdd) << 1) + off).Store(ref Unsafe.Add(ref combined, WideLength + row));
		}

		TVector top = TVector.Create(offset[WideRows - 1]);
		top.Store(ref Unsafe.Add(ref combined, RowLength * (WideRows - 1)));
		top.Store(ref Unsafe.Add(ref combined, WideLength + RowLength * (WideRows - 1)));
	}

	// The Montgomery reductions of two sets of twenty signed columns at row stride 8, each of a value in [0, 2^520), side by side so that each fills the latency of the other, then weak reductions: each result has limbs 0 to 8 below 2^26 and a value below 1.0001p if the value reduced is below 482p², whose reduction t/R + p is then below 2^260. Round k takes q = −t_k/p mod 2^26 and adds q·p·2^(26k): t_k + q·p0 is then a multiple of 2^26, which carries into column k + 1 exactly, and columns k + 1 to k + 9 take q·p_j. As the low limb of q·p0 is (−t_k) mod 2^26, that carry is ⌈t_k/2^26⌉ = ⌊(t_k + 2^26 − 1)/2^26⌋, which the arithmetic shift gives for either sign of t_k and which needs no q, plus ⌊q·p0/2^26⌋, so the next round waits only for that shift of q·p0, below 2^52, and one addition. A window of ten vectors holds columns k to k + 9; column k leaves it and column k + 10 comes in. The result, (t + Q·p)/2^260 for some Q below 2^260, is below t/R + p. Each round adds below 2^52 to a column and the carries below 2^37, so columns below 2^62.5 in magnitude stay below 2^63, and the arithmetic carries take them whatever their sign.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Reduce2(ref ulong columns, ref ulong columnsB, ref ulong result, ref ulong resultB)
	{
		if (TVector.RegisterCount >= 32)
		{
			Reduce2Wide(ref columns, ref columnsB, ref result, ref resultB);
		}
		else
		{
			Reduce1(ref columns, ref result);
			Reduce1(ref columnsB, ref resultB);
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void Reduce2Wide(ref ulong columns, ref ulong columnsB, ref ulong result, ref ulong resultB)
	{
		TVector mask = TVector.Create(Mask);
		TVector inverse = TVector.Create(NegativeInverse);
		TVector t0 = TVector.Load(in columns);
		TVector t1 = TVector.Load(in Unsafe.Add(ref columns, 8));
		TVector t2 = TVector.Load(in Unsafe.Add(ref columns, 16));
		TVector t3 = TVector.Load(in Unsafe.Add(ref columns, 24));
		TVector t4 = TVector.Load(in Unsafe.Add(ref columns, 32));
		TVector t5 = TVector.Load(in Unsafe.Add(ref columns, 40));
		TVector t6 = TVector.Load(in Unsafe.Add(ref columns, 48));
		TVector t7 = TVector.Load(in Unsafe.Add(ref columns, 56));
		TVector t8 = TVector.Load(in Unsafe.Add(ref columns, 64));
		TVector t9 = TVector.Load(in Unsafe.Add(ref columns, 72));
		TVector u0 = TVector.Load(in columnsB);
		TVector u1 = TVector.Load(in Unsafe.Add(ref columnsB, 8));
		TVector u2 = TVector.Load(in Unsafe.Add(ref columnsB, 16));
		TVector u3 = TVector.Load(in Unsafe.Add(ref columnsB, 24));
		TVector u4 = TVector.Load(in Unsafe.Add(ref columnsB, 32));
		TVector u5 = TVector.Load(in Unsafe.Add(ref columnsB, 40));
		TVector u6 = TVector.Load(in Unsafe.Add(ref columnsB, 48));
		TVector u7 = TVector.Load(in Unsafe.Add(ref columnsB, 56));
		TVector u8 = TVector.Load(in Unsafe.Add(ref columnsB, 64));
		TVector u9 = TVector.Load(in Unsafe.Add(ref columnsB, 72));
		ref ulong next = ref Unsafe.Add(ref columns, 80);
		ref ulong nextB = ref Unsafe.Add(ref columnsB, 80);

		for (int k = 0; k < 10; ++k)
		{
			TVector q = TVector.Multiply(t0, inverse) & mask;
			TVector r = TVector.Multiply(u0, inverse) & mask;
			t0 = t1 + TVector.ShiftRightArithmetic26(t0 + mask) + TVector.MultiplyByFactor(q, P1) + (TVector.MultiplyByFactor(q, P0) >>> 26);
			u0 = u1 + TVector.ShiftRightArithmetic26(u0 + mask) + TVector.MultiplyByFactor(r, P1) + (TVector.MultiplyByFactor(r, P0) >>> 26);
			t1 = t2 + TVector.MultiplyByFactor(q, P2);
			u1 = u2 + TVector.MultiplyByFactor(r, P2);
			t2 = t3 + TVector.MultiplyByFactor(q, P3);
			u2 = u3 + TVector.MultiplyByFactor(r, P3);
			t3 = t4 + TVector.MultiplyByFactor(q, P4);
			u3 = u4 + TVector.MultiplyByFactor(r, P4);
			t4 = t5 + TVector.MultiplyByFactor(q, P5);
			u4 = u5 + TVector.MultiplyByFactor(r, P5);
			t5 = t6 + TVector.MultiplyByFactor(q, P6);
			u5 = u6 + TVector.MultiplyByFactor(r, P6);
			t6 = t7 + TVector.MultiplyByFactor(q, P7);
			u6 = u7 + TVector.MultiplyByFactor(r, P7);
			t7 = t8 + TVector.MultiplyByFactor(q, P8);
			u7 = u8 + TVector.MultiplyByFactor(r, P8);
			t8 = t9 + TVector.MultiplyByFactor(q, P9);
			u8 = u9 + TVector.MultiplyByFactor(r, P9);
			t9 = TVector.Load(in next);
			u9 = TVector.Load(in nextB);
			next = ref Unsafe.Add(ref next, 8);
			nextB = ref Unsafe.Add(ref nextB, 8);
		}

		if (typeof(TVector) == typeof(SM9VectorAvx512))
		{
			CarryAndReduce(Avx512(t0), Avx512(t1), Avx512(t2), Avx512(t3), Avx512(t4), Avx512(t5), Avx512(t6), Avx512(t7), Avx512(t8), Avx512(t9), ref result);
			CarryAndReduce(Avx512(u0), Avx512(u1), Avx512(u2), Avx512(u3), Avx512(u4), Avx512(u5), Avx512(u6), Avx512(u7), Avx512(u8), Avx512(u9), ref resultB);
			return;
		}

		Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
		Carry(ref u0, ref u1, ref u2, ref u3, ref u4, ref u5, ref u6, ref u7, ref u8, ref u9);
		Store(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref result);
		Store(u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ref resultB);
		WeakReduce2(ref result, ref resultB);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Load(ref ulong rows, out TVector t0, out TVector t1, out TVector t2, out TVector t3, out TVector t4, out TVector t5, out TVector t6, out TVector t7, out TVector t8, out TVector t9)
	{
		t0 = TVector.Load(in rows);
		t1 = TVector.Load(in Unsafe.Add(ref rows, 8));
		t2 = TVector.Load(in Unsafe.Add(ref rows, 16));
		t3 = TVector.Load(in Unsafe.Add(ref rows, 24));
		t4 = TVector.Load(in Unsafe.Add(ref rows, 32));
		t5 = TVector.Load(in Unsafe.Add(ref rows, 40));
		t6 = TVector.Load(in Unsafe.Add(ref rows, 48));
		t7 = TVector.Load(in Unsafe.Add(ref rows, 56));
		t8 = TVector.Load(in Unsafe.Add(ref rows, 64));
		t9 = TVector.Load(in Unsafe.Add(ref rows, 72));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Store(TVector t0, TVector t1, TVector t2, TVector t3, TVector t4, TVector t5, TVector t6, TVector t7, TVector t8, TVector t9, ref ulong result)
	{
		t0.Store(ref result);
		t1.Store(ref Unsafe.Add(ref result, 8));
		t2.Store(ref Unsafe.Add(ref result, 16));
		t3.Store(ref Unsafe.Add(ref result, 24));
		t4.Store(ref Unsafe.Add(ref result, 32));
		t5.Store(ref Unsafe.Add(ref result, 40));
		t6.Store(ref Unsafe.Add(ref result, 48));
		t7.Store(ref Unsafe.Add(ref result, 56));
		t8.Store(ref Unsafe.Add(ref result, 64));
		t9.Store(ref Unsafe.Add(ref result, 72));
	}

	// The weak reductions of two carried vectors of ten limbs in place, side by side, in a unit of their own: inlined into Reduce2 they would leave it past the budget of the inliner.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void WeakReduce2(ref ulong x, ref ulong y)
	{
		WeakReduce(TVector.Load(in x), TVector.Load(in Unsafe.Add(ref x, 8)), TVector.Load(in Unsafe.Add(ref x, 16)), TVector.Load(in Unsafe.Add(ref x, 24)), TVector.Load(in Unsafe.Add(ref x, 32)), TVector.Load(in Unsafe.Add(ref x, 40)), TVector.Load(in Unsafe.Add(ref x, 48)), TVector.Load(in Unsafe.Add(ref x, 56)), TVector.Load(in Unsafe.Add(ref x, 64)), TVector.Load(in Unsafe.Add(ref x, 72)), ref x);
		WeakReduce(TVector.Load(in y), TVector.Load(in Unsafe.Add(ref y, 8)), TVector.Load(in Unsafe.Add(ref y, 16)), TVector.Load(in Unsafe.Add(ref y, 24)), TVector.Load(in Unsafe.Add(ref y, 32)), TVector.Load(in Unsafe.Add(ref y, 40)), TVector.Load(in Unsafe.Add(ref y, 48)), TVector.Load(in Unsafe.Add(ref y, 56)), TVector.Load(in Unsafe.Add(ref y, 64)), TVector.Load(in Unsafe.Add(ref y, 72)), ref y);
	}

	// Carries limbs 0 to 8 into the next, arithmetically, leaving them in [0, 2^26) and limb 9 with the rest.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Carry(ref TVector t0, ref TVector t1, ref TVector t2, ref TVector t3, ref TVector t4, ref TVector t5, ref TVector t6, ref TVector t7, ref TVector t8, ref TVector t9)
	{
		TVector mask = TVector.Create(Mask);
		t1 += TVector.ShiftRightArithmetic26(t0);
		t0 &= mask;
		t2 += TVector.ShiftRightArithmetic26(t1);
		t1 &= mask;
		t3 += TVector.ShiftRightArithmetic26(t2);
		t2 &= mask;
		t4 += TVector.ShiftRightArithmetic26(t3);
		t3 &= mask;
		t5 += TVector.ShiftRightArithmetic26(t4);
		t4 &= mask;
		t6 += TVector.ShiftRightArithmetic26(t5);
		t5 &= mask;
		t7 += TVector.ShiftRightArithmetic26(t6);
		t6 &= mask;
		t8 += TVector.ShiftRightArithmetic26(t7);
		t7 &= mask;
		t9 += TVector.ShiftRightArithmetic26(t8);
		t8 &= mask;
	}

	// For limbs 0 to 8 below 2^26 and a value below 2^261, so limb 9 below 2^27: subtracts q·p for q = ⌊L9·M/2^40⌋, M = ⌊2^40/(P9 + 1)⌋, which is ⌊L9/(P9 + 1)⌋ or one less, as L9·ε/2^40 < 2^−16 for ε = 2^40/(P9 + 1) − M < 0.097. As p < (P9 + 1)·2^234, q·p is at most the value. With L9 = n·(P9 + 1) + m, q = n leaves at most (L9 + 1)·2^234 − n·P9·2^234 = (n + m + 1)·2^234 ≤ (P9 + 45)·2^234; q = n − 1 happens only for m < L9·(P9 + 1)·ε/2^40, below 36, and leaves at most (P9 + n + m + 1)·2^234 ≤ (P9 + 80)·2^234, so the result is below 1.0001p. q is below 45, so q·p_j is below 2^31.5; each limb takes 2^32 and gives 2^6 to the one above, which keeps every limb below the top one positive while the value stays, and the top limb ends as the top of the result, not negative.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WeakReduce(TVector t0, TVector t1, TVector t2, TVector t3, TVector t4, TVector t5, TVector t6, TVector t7, TVector t8, TVector t9, ref ulong result)
	{
		TVector mask = TVector.Create(Mask);
		TVector q = TVector.MultiplyByFactor(t9, QuotientMultiplier) >>> 40;
		TVector bias = TVector.Create(1UL << 32);
		TVector borrow = TVector.Create((1UL << 32) - (1UL << 6));
		t0 = t0 + bias - TVector.MultiplyByFactor(q, P0);
		t1 = t1 + borrow - TVector.MultiplyByFactor(q, P1) + (t0 >>> 26);
		t2 = t2 + borrow - TVector.MultiplyByFactor(q, P2) + (t1 >>> 26);
		t3 = t3 + borrow - TVector.MultiplyByFactor(q, P3) + (t2 >>> 26);
		t4 = t4 + borrow - TVector.MultiplyByFactor(q, P4) + (t3 >>> 26);
		t5 = t5 + borrow - TVector.MultiplyByFactor(q, P5) + (t4 >>> 26);
		t6 = t6 + borrow - TVector.MultiplyByFactor(q, P6) + (t5 >>> 26);
		t7 = t7 + borrow - TVector.MultiplyByFactor(q, P7) + (t6 >>> 26);
		t8 = t8 + borrow - TVector.MultiplyByFactor(q, P8) + (t7 >>> 26);
		t9 = t9 - TVector.Create(1UL << 6) - TVector.MultiplyByFactor(q, P9) + (t8 >>> 26);
		(t0 & mask).Store(ref result);
		(t1 & mask).Store(ref Unsafe.Add(ref result, 8));
		(t2 & mask).Store(ref Unsafe.Add(ref result, 16));
		(t3 & mask).Store(ref Unsafe.Add(ref result, 24));
		(t4 & mask).Store(ref Unsafe.Add(ref result, 32));
		(t5 & mask).Store(ref Unsafe.Add(ref result, 40));
		(t6 & mask).Store(ref Unsafe.Add(ref result, 48));
		(t7 & mask).Store(ref Unsafe.Add(ref result, 56));
		(t8 & mask).Store(ref Unsafe.Add(ref result, 64));
		t9.Store(ref Unsafe.Add(ref result, 72));
	}

	// The ten rows at rows, with limbs below 2^62 and values below 2^261, weakly reduced in place: carried, then as WeakReduce.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void WeakReduceRows(ref ulong rows)
	{
		for (int v = 0; v < VectorCount; ++v)
		{
			ref ulong x = ref Unsafe.Add(ref rows, v * TVector.Count);
			Load(ref x, out TVector t0, out TVector t1, out TVector t2, out TVector t3, out TVector t4, out TVector t5, out TVector t6, out TVector t7, out TVector t8, out TVector t9);
			Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
			WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref x);
		}
	}

	// The twenty rows of an element weakly reduced in place, as WeakReduceRows for each component; with 32 registers both go side by side.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void WeakReduceElement(ref ulong rows)
	{
		if (TVector.RegisterCount < 32)
		{
			WeakReduceRows(ref rows);
			WeakReduceRows(ref Unsafe.Add(ref rows, ComponentLength));
			return;
		}

		for (int v = 0; v < VectorCount; ++v)
		{
			ref ulong x = ref Unsafe.Add(ref rows, v * TVector.Count);
			ref ulong y = ref Unsafe.Add(ref x, ComponentLength);
			Load(ref x, out TVector t0, out TVector t1, out TVector t2, out TVector t3, out TVector t4, out TVector t5, out TVector t6, out TVector t7, out TVector t8, out TVector t9);
			Load(ref y, out TVector u0, out TVector u1, out TVector u2, out TVector u3, out TVector u4, out TVector u5, out TVector u6, out TVector u7, out TVector u8, out TVector u9);
			Carry(ref t0, ref t1, ref t2, ref t3, ref t4, ref t5, ref t6, ref t7, ref t8, ref t9);
			Carry(ref u0, ref u1, ref u2, ref u3, ref u4, ref u5, ref u6, ref u7, ref u8, ref u9);
			WeakReduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, ref x);
			WeakReduce(u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ref y);
		}
	}
}
