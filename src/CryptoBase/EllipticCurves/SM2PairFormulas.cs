using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// k·P and u1·G + u2·Q for one point at a time on the two lanes of TField, SM2Field29x2: each round of a formula takes two products that need only those of the rounds before, one in each lane. A point keeps X in both lanes of XX and Y and Z in the lanes of YZ; [a | b] holds a in lane 0 and b in lane 1, and a lane that no later step reads may hold anything. The field holds its nine limbs as nine vectors in a row, which the formulas read through Limbs.
// Bounds, with those of SM2Field29: a point that a formula takes has X and Z below 2p in limbs 0 to 7 below 2^29 and limb 8 below 2^24 + 2^5, as Reduce, which ends every formula, leaves them, and Y as Reduce leaves it or, from an entry, 4p − Y as ConditionalNegate leaves it, in limbs at most those of 4p, below 2^30; AddAffine takes Y as Reduce leaves it. An entry holds such X, Y, negated or not, and Z, and Z² and Z³ from products; joining limbs 2m and 2m + 1 into one ulong and splitting them again adds at most 1 to limbs 1, 3, 5 and 7. The values that go into products are below 9.4p, so every product is below 2.8p, its limb 8 below 2^26 − 2, and every subtrahend is a product, a product doubled, the sum of three products or a coordinate that Reduce left, with limbs at most those of the 4p, 8p or 12p added to it. A product or a coordinate plus 4p less such a subtrahend has limbs below 3·2^29 + 2^6, and the formulas multiply such a difference only by a product, a coordinate or a value carried by one step: each limb but limb 8 keeps its low 29 bits and passes the rest to the limb above, which leaves limbs below 2^29 + 8 for limbs below 2^32. With the bounds of each formula below, the limbs of the operands of every product have bounds whose product is below 6.1·2^58, within the 9·X·Y ≤ 2^64 − 2^54 of Multiply, every input of Square has limbs below 2^30 + 2^8, and every input of Reduce has limbs below 7·2^29 + 2^6 and limb 8 below 2^28.
internal static class SM2PairFormulas<TField> where TField : unmanaged, ISM2Field29Lanes<TField>
{
	// The windows of ECGroup.Multiply, whose digits Recode gives.
	private const int WindowWidth = 5;

	private const int TableLength = 1 << WindowWidth - 1;

	// [X | Y] and [Z³ | Z] of an entry, limbs 2m and 2m + 1 joined into one ulong for m from 0 to 3 and limb 8 alone, the two lanes interleaved, and then Z², so that an entry takes 25 limbs.
	private const int EntryLength = 25;

	private const int CubeOffset = 10;

	private const int SquareOffset = 20;

	// The NAF of u2 in ECVariableTimeGroup.MultiplyAdd, over Q, 3Q, …, 15Q.
	private const int PointWidth = 5;

	private const int OddLength = 1 << PointWidth - 2;

	// The windows of ECGroup.Multiply: digits from Recode, the table of 1·P to 16·P and, for each digit, five doublings and the addition of its entry. As there, the points of an addition are neither equal nor opposite except where the masks cover them and in window 0 for k = n − 6, where they are equal and the double takes the place of the sum. The table holds Jacobian points with their Z² and Z³ instead of affine ones, so it needs no inversion. Neither the time nor the addresses depend on k or P, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		Debug.Assert(TField.LaneCount is 2 && Unsafe.SizeOf<TField>() == 9 * Unsafe.SizeOf<Vector128<ulong>>());

		Span<sbyte> digits = stackalloc sbyte[ECGroup<SM2Curve, SM2Field52, SM2Order>.DigitCount(WindowWidth)];
		Span<ulong> table = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> packed = stackalloc ulong[EntryLength];
		Span<ulong> masks = stackalloc ulong[8];
		Span<ulong> zero = masks.Slice(0, 2);
		Span<ulong> infinity = masks.Slice(2, 2);
		Span<ulong> negative = masks.Slice(4, 2);
		Span<ulong> equal = masks.Slice(6, 2);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in scalar, WindowWidth, digits);
		BuildTable(in point, table);
		Unsafe.SkipInit(out SM2PairEntry<TField> entry);
		Unsafe.SkipInit(out SM2PairPoint<TField> selected);
		Unsafe.SkipInit(out SM2PairPoint<TField> sum);
		Unsafe.SkipInit(out SM2PairPoint<TField> twice);
		Unsafe.SkipInit(out SM2PairPoint<TField> total);
		Select(table, digits[^1], packed, negative, out entry);
		ToPoint(in entry, out total);
		// A lane mask is set in both lanes. The sum is the point at infinity just while every digit so far is 0, as no sum of digits other than 0 is a multiple of n, which the masks track instead of Z.
		infinity.Fill(ZeroMask((ulong)digits[^1]));
		ReadOnlySpan<ulong> limbs = FieldElement<SM2Order>.GetLimbs(in scalar);
		ReadOnlySpan<ulong> n = SM2Order.Modulus;
		equal.Fill(ZeroMask(limbs[0] ^ n[0] - 6 | limbs[1] ^ n[1] | limbs[2] ^ n[2] | limbs[3] ^ n[3]));

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			for (int j = 0; j < WindowWidth; ++j)
			{
				Double(in total, out total);
			}

			Select(table, digits[i], packed, negative, out entry);
			zero.Fill(ZeroMask((ulong)digits[i]));
			Add(in total, in entry, out sum);

			if (i is 0)
			{
				Double(in total, out twice);
				SM2PairPoint<TField>.ConditionalSelect(in equal[0], in twice, in sum, out sum);
			}

			ToPoint(in entry, out selected);
			SM2PairPoint<TField>.ConditionalSelect(in infinity[0], in selected, in sum, out sum);
			SM2PairPoint<TField>.ConditionalSelect(in zero[0], in total, in sum, out total);
			infinity[0] &= zero[0];
			infinity[1] &= zero[1];
		}

		// The point at infinity, for k = 0, comes out as (0, 0, 0), as from ECGroup.Multiply.
		ToJacobian(in total, out result);
		JacobianPoint<SM2Field52> cleared = default;
		JacobianPoint<SM2Field52>.ConditionalSelect(infinity[0], in cleared, in result, out result);
		digits.ZeroMemory();
		table.ZeroMemory();
		packed.ZeroMemory();
		masks.ZeroMemory();
		entry.ZeroMemory();
		selected.ZeroMemory();
		sum.ZeroMemory();
		twice.ZeroMemory();
		total.ZeroMemory();
	}

	// Sets result to u1·G + u2·Q for u1 and u2 below n and a point Q on the curve, by the digits of ECVariableTimeGroup.MultiplyAdd: the NAF of u1 of width 8 over the affine odd multiples of G in ECVariableTimeGeneratorTable, which AddAffine adds, and that of u2 of width 5 over Q, 3Q, …, 15Q, kept as entries with their Z² and Z³. Every input is public, so the time and the branches depend on them.
	[SkipLocalsInit]
	internal static void MultiplyAdd(in FieldElement<SM2Order> u1, in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> u2, out JacobianPoint<SM2Field52> result)
	{
		int count = ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.DigitCount;
		Span<sbyte> baseDigits = stackalloc sbyte[count];
		Span<sbyte> pointDigits = stackalloc sbyte[count];
		int top = Math.Max(ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in u1, ECVariableTimeGeneratorTable<SM2Curve, SM2Field52, SM2Order>.Width, baseDigits), ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in u2, PointWidth, pointDigits));
		ReadOnlySpan<AffinePoint<SM2Field52>> baseMultiples = ECVariableTimeGeneratorTable<SM2Curve, SM2Field52, SM2Order>.Entries;
		Span<SM2PairEntry<TField>> pointMultiples = stackalloc SM2PairEntry<TField>[OddLength];
		Span<ulong> negative = [0, ulong.MaxValue];
		BuildOddMultiples(in point, pointMultiples);
		Unsafe.SkipInit(out SM2PairPoint<TField> total);
		Unsafe.SkipInit(out SM2PairEntry<TField> entry);
		Unsafe.SkipInit(out TField affine);
		bool infinity = true;

		for (int i = top; i >= 0; --i)
		{
			if (!infinity)
			{
				Double(in total, out total);
			}

			int digit = baseDigits[i];

			if (digit is not 0)
			{
				FromAffine(in baseMultiples[Math.Abs(digit) >> 1], out affine);

				if (digit < 0)
				{
					TField.ConditionalNegate(in negative[0], ref affine);
				}

				AddAffineVariableTime(ref total, ref infinity, in affine);
			}

			digit = pointDigits[i];

			if (digit is not 0)
			{
				entry = pointMultiples[Math.Abs(digit) >> 1];

				if (digit < 0)
				{
					TField.ConditionalNegate(in negative[0], ref entry.XY);
				}

				AddVariableTime(ref total, ref infinity, in entry);
			}
		}

		if (infinity)
		{
			result = default;
			return;
		}

		ToJacobian(in total, out result);
	}

	// total + entry, where total may be the point at infinity, which infinity tells, and the points may be equal or opposite. Z3 = Z1·Z2·H of Add is 0 just for H = 0, so for equal or opposite points, which its formulas do not cover; then the formulas of SM2Field52 tell them apart. The points are public, so the cases may branch. A point made of an entry goes through Reduce, as AddAffine takes its Y.
	[SkipLocalsInit]
	private static void AddVariableTime(ref SM2PairPoint<TField> total, ref bool infinity, in SM2PairEntry<TField> entry)
	{
		if (infinity)
		{
			ToPoint(in entry, out total);
			TField.Reduce(in total.YZ, out total.YZ);
			infinity = false;
			return;
		}

		SM2PairPoint<TField> left = total;
		Add(in left, in entry, out total);

		if (!IsZeroZ(in total))
		{
			return;
		}

		ToJacobian(in left, out JacobianPoint<SM2Field52> x);
		ToPoint(in entry, out SM2PairPoint<TField> right);
		ToJacobian(in right, out JacobianPoint<SM2Field52> y);

		if (ECGroup<SM2Curve, SM2Field52, SM2Order>.AddDistinct(in x, in y, out _) is 0)
		{
			infinity = true;
			return;
		}

		Double(in left, out total);
	}

	// As AddVariableTime for an affine entry [x | y] that Reduce left, Y negated or not, by AddAffine, whose Z3 = Z1·H is 0 just for H = 0 as well.
	[SkipLocalsInit]
	private static void AddAffineVariableTime(ref SM2PairPoint<TField> total, ref bool infinity, in TField affine)
	{
		if (infinity)
		{
			ToPoint(in affine, out total);
			TField.Reduce(in total.YZ, out total.YZ);
			infinity = false;
			return;
		}

		SM2PairPoint<TField> left = total;
		AddAffine(ref total, in affine);

		if (!IsZeroZ(in total))
		{
			return;
		}

		ToJacobian(in left, out JacobianPoint<SM2Field52> x);
		ToPoint(in affine, out SM2PairPoint<TField> right);
		ToJacobian(in right, out JacobianPoint<SM2Field52> y);

		if (ECGroup<SM2Curve, SM2Field52, SM2Order>.AddDistinct(in x, in y, out _) is 0)
		{
			infinity = true;
			return;
		}

		Double(in left, out total);
	}

	// Whether Z of a point that Reduce left, below 2p in limbs 0 to 7 below 2^29 and limb 8 below 2^24 + 2^5, is 0 mod p: its limbs then are those of 0 or of p.
	private static bool IsZeroZ(in SM2PairPoint<TField> point)
	{
		ref Vector128<ulong> yz = ref Limbs(in point.YZ);
		Vector128<ulong> low = Vector128.Create(SM2Field29.PLow);
		Vector128<ulong> zero = yz | Unsafe.Add(ref yz, 1) | Unsafe.Add(ref yz, 2) | Unsafe.Add(ref yz, 3) | Unsafe.Add(ref yz, 4) | Unsafe.Add(ref yz, 5) | Unsafe.Add(ref yz, 6) | Unsafe.Add(ref yz, 7) | Unsafe.Add(ref yz, 8);
		Vector128<ulong> modulus = yz ^ low | Unsafe.Add(ref yz, 1) ^ low | Unsafe.Add(ref yz, 2) ^ Vector128.Create(SM2Field29.P2) | Unsafe.Add(ref yz, 3) ^ Vector128.Create(SM2Field29.P3) | Unsafe.Add(ref yz, 4) ^ low | Unsafe.Add(ref yz, 5) ^ low | Unsafe.Add(ref yz, 6) ^ low | Unsafe.Add(ref yz, 7) ^ Vector128.Create(SM2Field29.P7) | Unsafe.Add(ref yz, 8) ^ Vector128.Create(SM2Field29.P8);
		return zero.GetElement(1) is 0 || modulus.GetElement(1) is 0;
	}

	// 2·point for a = −3 by the formulas of ECFormulas.Double with α = 3(X − δ)(X + δ), in four rounds: [γ | δ] = [Y² | Z²], [4β | α] = [X·4γ | (X − δ)·3(X + δ)], [α² | 4γ²] = [α² | (2γ)²] and [α·D | Y·Z] for D = 12β − α² = 4β − X3, which give X3 = α² − 8β, Y3 = α·D − 8γ² and Z3 = 2·Y·Z. The right of the second round, [4γ | 3(X + δ)] in limbs below 6·2^29 + 2^8, goes in carried, in limbs below 2^29 + 8, against [X | X − δ + 4p] in limbs below 3·2^29; 2γ has limbs below 2^30 + 2^8, D + 4p = 3·4β + 4p − α² limbs below 5·2^29 + 2^8 against α, and X3 + 8p and Y3 + 8p limbs below 5·2^29 + 2^6. The point at infinity gives some point, which the masks discard. The point is read before result is written, so result may be the point.
	[SkipLocalsInit]
	private static void Double(in SM2PairPoint<TField> point, out SM2PairPoint<TField> result)
	{
		Unsafe.SkipInit(out TField left);
		Unsafe.SkipInit(out TField right);
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		ref Vector128<ulong> xx = ref Limbs(in point.XX);
		ref Vector128<ulong> yz = ref Limbs(in point.YZ);
		TField.Square(in point.YZ, out TField squares);
		Vector128<ulong> x0 = Unsafe.Add(ref xx, 0);
		Vector128<ulong> s0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0);
		Vector128<ulong> a0 = x0 + s0;
		Vector128<ulong> t0 = Blend(s0 << 2, a0 + (a0 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(x0, x0 + Vector128.Create(SM2Field29.FourP0) - s0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = t0 & mask;
		Vector128<ulong> x1 = Unsafe.Add(ref xx, 1);
		Vector128<ulong> s1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1);
		Vector128<ulong> a1 = x1 + s1;
		Vector128<ulong> t1 = Blend(s1 << 2, a1 + (a1 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(x1, x1 + Vector128.Create(SM2Field29.FourP1) - s1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = (t1 & mask) + (t0 >> SM2Field29.Bits);
		Vector128<ulong> x2 = Unsafe.Add(ref xx, 2);
		Vector128<ulong> s2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2);
		Vector128<ulong> a2 = x2 + s2;
		Vector128<ulong> t2 = Blend(s2 << 2, a2 + (a2 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(x2, x2 + Vector128.Create(SM2Field29.FourP2) - s2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = (t2 & mask) + (t1 >> SM2Field29.Bits);
		Vector128<ulong> x3 = Unsafe.Add(ref xx, 3);
		Vector128<ulong> s3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3);
		Vector128<ulong> a3 = x3 + s3;
		Vector128<ulong> t3 = Blend(s3 << 2, a3 + (a3 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(x3, x3 + Vector128.Create(SM2Field29.FourP3) - s3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = (t3 & mask) + (t2 >> SM2Field29.Bits);
		Vector128<ulong> x4 = Unsafe.Add(ref xx, 4);
		Vector128<ulong> s4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4);
		Vector128<ulong> a4 = x4 + s4;
		Vector128<ulong> t4 = Blend(s4 << 2, a4 + (a4 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(x4, x4 + Vector128.Create(SM2Field29.FourPMiddle) - s4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = (t4 & mask) + (t3 >> SM2Field29.Bits);
		Vector128<ulong> x5 = Unsafe.Add(ref xx, 5);
		Vector128<ulong> s5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5);
		Vector128<ulong> a5 = x5 + s5;
		Vector128<ulong> t5 = Blend(s5 << 2, a5 + (a5 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(x5, x5 + Vector128.Create(SM2Field29.FourPMiddle) - s5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = (t5 & mask) + (t4 >> SM2Field29.Bits);
		Vector128<ulong> x6 = Unsafe.Add(ref xx, 6);
		Vector128<ulong> s6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6);
		Vector128<ulong> a6 = x6 + s6;
		Vector128<ulong> t6 = Blend(s6 << 2, a6 + (a6 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(x6, x6 + Vector128.Create(SM2Field29.FourPMiddle) - s6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = (t6 & mask) + (t5 >> SM2Field29.Bits);
		Vector128<ulong> x7 = Unsafe.Add(ref xx, 7);
		Vector128<ulong> s7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7);
		Vector128<ulong> a7 = x7 + s7;
		Vector128<ulong> t7 = Blend(s7 << 2, a7 + (a7 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(x7, x7 + Vector128.Create(SM2Field29.FourP7) - s7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = (t7 & mask) + (t6 >> SM2Field29.Bits);
		Vector128<ulong> x8 = Unsafe.Add(ref xx, 8);
		Vector128<ulong> s8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8);
		Vector128<ulong> a8 = x8 + s8;
		Vector128<ulong> t8 = Blend(s8 << 2, a8 + (a8 << 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(x8, x8 + Vector128.Create(SM2Field29.FourP8) - s8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = t8 + (t7 >> SM2Field29.Bits);
		TField.Multiply(in left, in right, out TField products);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Cross(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8) << 1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8));
		TField.Square(in left, out TField quartics);
		Vector128<ulong> m0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Vector128<ulong> q0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 0);
		Vector128<ulong> e0 = q0 + Vector128.Create(2 * SM2Field29.FourP0) - (m0 << 1);
		Vector128<ulong> yz0 = Unsafe.Add(ref yz, 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0) = Low(e0, e0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Cross(yz0, m0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Blend(m0 + (m0 << 1) + Vector128.Create(SM2Field29.FourP0) - q0, yz0);
		Vector128<ulong> m1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Vector128<ulong> q1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 1);
		Vector128<ulong> e1 = q1 + Vector128.Create(2 * SM2Field29.FourP1) - (m1 << 1);
		Vector128<ulong> yz1 = Unsafe.Add(ref yz, 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1) = Low(e1, e1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Cross(yz1, m1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Blend(m1 + (m1 << 1) + Vector128.Create(SM2Field29.FourP1) - q1, yz1);
		Vector128<ulong> m2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Vector128<ulong> q2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 2);
		Vector128<ulong> e2 = q2 + Vector128.Create(2 * SM2Field29.FourP2) - (m2 << 1);
		Vector128<ulong> yz2 = Unsafe.Add(ref yz, 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2) = Low(e2, e2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Cross(yz2, m2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Blend(m2 + (m2 << 1) + Vector128.Create(SM2Field29.FourP2) - q2, yz2);
		Vector128<ulong> m3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Vector128<ulong> q3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 3);
		Vector128<ulong> e3 = q3 + Vector128.Create(2 * SM2Field29.FourP3) - (m3 << 1);
		Vector128<ulong> yz3 = Unsafe.Add(ref yz, 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3) = Low(e3, e3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Cross(yz3, m3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Blend(m3 + (m3 << 1) + Vector128.Create(SM2Field29.FourP3) - q3, yz3);
		Vector128<ulong> m4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Vector128<ulong> q4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 4);
		Vector128<ulong> e4 = q4 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (m4 << 1);
		Vector128<ulong> yz4 = Unsafe.Add(ref yz, 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4) = Low(e4, e4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Cross(yz4, m4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Blend(m4 + (m4 << 1) + Vector128.Create(SM2Field29.FourPMiddle) - q4, yz4);
		Vector128<ulong> m5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Vector128<ulong> q5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 5);
		Vector128<ulong> e5 = q5 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (m5 << 1);
		Vector128<ulong> yz5 = Unsafe.Add(ref yz, 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5) = Low(e5, e5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Cross(yz5, m5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Blend(m5 + (m5 << 1) + Vector128.Create(SM2Field29.FourPMiddle) - q5, yz5);
		Vector128<ulong> m6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Vector128<ulong> q6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 6);
		Vector128<ulong> e6 = q6 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (m6 << 1);
		Vector128<ulong> yz6 = Unsafe.Add(ref yz, 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6) = Low(e6, e6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Cross(yz6, m6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Blend(m6 + (m6 << 1) + Vector128.Create(SM2Field29.FourPMiddle) - q6, yz6);
		Vector128<ulong> m7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Vector128<ulong> q7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 7);
		Vector128<ulong> e7 = q7 + Vector128.Create(2 * SM2Field29.FourP7) - (m7 << 1);
		Vector128<ulong> yz7 = Unsafe.Add(ref yz, 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7) = Low(e7, e7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Cross(yz7, m7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Blend(m7 + (m7 << 1) + Vector128.Create(SM2Field29.FourP7) - q7, yz7);
		Vector128<ulong> m8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Vector128<ulong> q8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 8);
		Vector128<ulong> e8 = q8 + Vector128.Create(2 * SM2Field29.FourP8) - (m8 << 1);
		Vector128<ulong> yz8 = Unsafe.Add(ref yz, 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8) = Low(e8, e8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Cross(yz8, m8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Blend(m8 + (m8 << 1) + Vector128.Create(SM2Field29.FourP8) - q8, yz8);
		TField.Reduce(in squares, out result.XX);
		TField.Multiply(in left, in right, out products);
		Vector128<ulong> n0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Vector128<ulong> g0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(n0 + Vector128.Create(2 * SM2Field29.FourP0) - (High(g0, g0) << 1), n0 << 1);
		Vector128<ulong> n1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Vector128<ulong> g1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(n1 + Vector128.Create(2 * SM2Field29.FourP1) - (High(g1, g1) << 1), n1 << 1);
		Vector128<ulong> n2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Vector128<ulong> g2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(n2 + Vector128.Create(2 * SM2Field29.FourP2) - (High(g2, g2) << 1), n2 << 1);
		Vector128<ulong> n3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Vector128<ulong> g3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(n3 + Vector128.Create(2 * SM2Field29.FourP3) - (High(g3, g3) << 1), n3 << 1);
		Vector128<ulong> n4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Vector128<ulong> g4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(n4 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (High(g4, g4) << 1), n4 << 1);
		Vector128<ulong> n5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Vector128<ulong> g5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(n5 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (High(g5, g5) << 1), n5 << 1);
		Vector128<ulong> n6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Vector128<ulong> g6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(n6 + Vector128.Create(2 * SM2Field29.FourPMiddle) - (High(g6, g6) << 1), n6 << 1);
		Vector128<ulong> n7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Vector128<ulong> g7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(n7 + Vector128.Create(2 * SM2Field29.FourP7) - (High(g7, g7) << 1), n7 << 1);
		Vector128<ulong> n8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Vector128<ulong> g8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref quartics), 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(n8 + Vector128.Create(2 * SM2Field29.FourP8) - (High(g8, g8) << 1), n8 << 1);
		TField.Reduce(in left, out result.YZ);
	}

	// point + entry by the formulas of ECFormulas.AddDistinct, without the factors 2 and 4 of R, I and Z3, for an entry (X2, Y2, Z2) neither equal nor opposite to the point, and neither of them the point at infinity: such lanes give some point, which the masks discard. Seven rounds: [Z1² | U1] = [Z1·Z1 | X1·Z2²], [U2 | Y2·Z1] = [X2·Z1² | Y2·Z1], [H² | S2] = [H·H | Y2·Z1·Z1²], [H³ | V] = [H·H² | U1·H²], [S1 | Z1·Z2] = [Y1·Z2³ | Z1·Z2], [R² | Z3] = [R·R | Z1·Z2·H] and [R·(V − X3) | S1·H³] for H = U2 − U1 and R = S2 − S1, which give X3 = R² − H³ − 2V and Y3 = R·(V − X3) − S1·H³; V − X3 = 3V + H³ − R² needs no X3. H + 4p and R + 4p, in limbs below 3·2^29 + 2^6, go into the products carried, in limbs below 2^29 + 3; V − X3 + 4p has limbs below 6·2^29 + 2^8, X3 + 12p limbs below 7·2^29 + 2^6 and Y3 + 4p limbs below 3·2^29 + 2^6. The point is read before result is written, so result may be the point.
	[SkipLocalsInit]
	internal static void Add(in SM2PairPoint<TField> point, in SM2PairEntry<TField> entry, out SM2PairPoint<TField> result)
	{
		Unsafe.SkipInit(out TField left);
		Unsafe.SkipInit(out TField right);
		Unsafe.SkipInit(out TField xs);
		ref Vector128<ulong> xx = ref Limbs(in point.XX);
		ref Vector128<ulong> yz = ref Limbs(in point.YZ);
		// Z2² goes through entry instead of a reference of its own, which leaves four references live across the products with result: an odd number of saved registers would leave the locals at offsets that the vector loads and stores of Arm64 cannot encode.
		// S1 and Z1·Z2 need only the inputs, so the rounds before can overlap them.
		TField.Multiply(in point.YZ, in entry.CubeZ, out TField first);
		Vector128<ulong> yz0 = Unsafe.Add(ref yz, 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Cross(Unsafe.Add(ref xx, 0), yz0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 0), yz0);
		Vector128<ulong> yz1 = Unsafe.Add(ref yz, 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Cross(Unsafe.Add(ref xx, 1), yz1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 1), yz1);
		Vector128<ulong> yz2 = Unsafe.Add(ref yz, 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Cross(Unsafe.Add(ref xx, 2), yz2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 2), yz2);
		Vector128<ulong> yz3 = Unsafe.Add(ref yz, 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Cross(Unsafe.Add(ref xx, 3), yz3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 3), yz3);
		Vector128<ulong> yz4 = Unsafe.Add(ref yz, 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Cross(Unsafe.Add(ref xx, 4), yz4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 4), yz4);
		Vector128<ulong> yz5 = Unsafe.Add(ref yz, 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Cross(Unsafe.Add(ref xx, 5), yz5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 5), yz5);
		Vector128<ulong> yz6 = Unsafe.Add(ref yz, 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Cross(Unsafe.Add(ref xx, 6), yz6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 6), yz6);
		Vector128<ulong> yz7 = Unsafe.Add(ref yz, 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Cross(Unsafe.Add(ref xx, 7), yz7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 7), yz7);
		Vector128<ulong> yz8 = Unsafe.Add(ref yz, 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Cross(Unsafe.Add(ref xx, 8), yz8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Cross(Unsafe.Add(ref Limbs(in entry.SquareZ), 8), yz8);
		TField.Multiply(in left, in right, out TField squares);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0), Unsafe.Add(ref yz, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1), Unsafe.Add(ref yz, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2), Unsafe.Add(ref yz, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3), Unsafe.Add(ref yz, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4), Unsafe.Add(ref yz, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5), Unsafe.Add(ref yz, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6), Unsafe.Add(ref yz, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7), Unsafe.Add(ref yz, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8), Unsafe.Add(ref yz, 8));
		TField.Multiply(in entry.XY, in right, out TField products);
		// H carried.
		Vector128<ulong> a0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0);
		Vector128<ulong> c0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Vector128<ulong> d0 = c0 + Vector128.Create(SM2Field29.FourP0) - High(a0, a0);
		Vector128<ulong> h0 = d0 & Vector128.Create(SM2Field29.Mask);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(h0, c0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(h0, a0);
		Vector128<ulong> a1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1);
		Vector128<ulong> c1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Vector128<ulong> d1 = c1 + Vector128.Create(SM2Field29.FourP1) - High(a1, a1);
		Vector128<ulong> h1 = (d1 & Vector128.Create(SM2Field29.Mask)) + (d0 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(h1, c1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(h1, a1);
		Vector128<ulong> a2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2);
		Vector128<ulong> c2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Vector128<ulong> d2 = c2 + Vector128.Create(SM2Field29.FourP2) - High(a2, a2);
		Vector128<ulong> h2 = (d2 & Vector128.Create(SM2Field29.Mask)) + (d1 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(h2, c2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(h2, a2);
		Vector128<ulong> a3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3);
		Vector128<ulong> c3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Vector128<ulong> d3 = c3 + Vector128.Create(SM2Field29.FourP3) - High(a3, a3);
		Vector128<ulong> h3 = (d3 & Vector128.Create(SM2Field29.Mask)) + (d2 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(h3, c3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(h3, a3);
		Vector128<ulong> a4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4);
		Vector128<ulong> c4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Vector128<ulong> d4 = c4 + Vector128.Create(SM2Field29.FourPMiddle) - High(a4, a4);
		Vector128<ulong> h4 = (d4 & Vector128.Create(SM2Field29.Mask)) + (d3 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(h4, c4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(h4, a4);
		Vector128<ulong> a5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5);
		Vector128<ulong> c5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Vector128<ulong> d5 = c5 + Vector128.Create(SM2Field29.FourPMiddle) - High(a5, a5);
		Vector128<ulong> h5 = (d5 & Vector128.Create(SM2Field29.Mask)) + (d4 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(h5, c5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(h5, a5);
		Vector128<ulong> a6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6);
		Vector128<ulong> c6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Vector128<ulong> d6 = c6 + Vector128.Create(SM2Field29.FourPMiddle) - High(a6, a6);
		Vector128<ulong> h6 = (d6 & Vector128.Create(SM2Field29.Mask)) + (d5 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(h6, c6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(h6, a6);
		Vector128<ulong> a7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7);
		Vector128<ulong> c7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Vector128<ulong> d7 = c7 + Vector128.Create(SM2Field29.FourP7) - High(a7, a7);
		Vector128<ulong> h7 = (d7 & Vector128.Create(SM2Field29.Mask)) + (d6 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(h7, c7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(h7, a7);
		Vector128<ulong> a8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8);
		Vector128<ulong> c8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Vector128<ulong> d8 = c8 + Vector128.Create(SM2Field29.FourP8) - High(a8, a8);
		Vector128<ulong> h8 = d8 + (d7 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(h8, c8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(h8, a8);
		TField.Multiply(in left, in right, out products);
		// R carried.
		Vector128<ulong> f0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(h0, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(f0, f0);
		Vector128<ulong> b0 = High(f0, f0) + Vector128.Create(SM2Field29.FourP0) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 0);
		Vector128<ulong> r0 = b0 & Vector128.Create(SM2Field29.Mask);
		Vector128<ulong> f1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(h1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(f1, f1);
		Vector128<ulong> b1 = High(f1, f1) + Vector128.Create(SM2Field29.FourP1) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 1);
		Vector128<ulong> r1 = (b1 & Vector128.Create(SM2Field29.Mask)) + (b0 >> SM2Field29.Bits);
		Vector128<ulong> f2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(h2, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(f2, f2);
		Vector128<ulong> b2 = High(f2, f2) + Vector128.Create(SM2Field29.FourP2) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 2);
		Vector128<ulong> r2 = (b2 & Vector128.Create(SM2Field29.Mask)) + (b1 >> SM2Field29.Bits);
		Vector128<ulong> f3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(h3, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(f3, f3);
		Vector128<ulong> b3 = High(f3, f3) + Vector128.Create(SM2Field29.FourP3) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 3);
		Vector128<ulong> r3 = (b3 & Vector128.Create(SM2Field29.Mask)) + (b2 >> SM2Field29.Bits);
		Vector128<ulong> f4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(h4, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(f4, f4);
		Vector128<ulong> b4 = High(f4, f4) + Vector128.Create(SM2Field29.FourPMiddle) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 4);
		Vector128<ulong> r4 = (b4 & Vector128.Create(SM2Field29.Mask)) + (b3 >> SM2Field29.Bits);
		Vector128<ulong> f5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(h5, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(f5, f5);
		Vector128<ulong> b5 = High(f5, f5) + Vector128.Create(SM2Field29.FourPMiddle) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 5);
		Vector128<ulong> r5 = (b5 & Vector128.Create(SM2Field29.Mask)) + (b4 >> SM2Field29.Bits);
		Vector128<ulong> f6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(h6, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(f6, f6);
		Vector128<ulong> b6 = High(f6, f6) + Vector128.Create(SM2Field29.FourPMiddle) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 6);
		Vector128<ulong> r6 = (b6 & Vector128.Create(SM2Field29.Mask)) + (b5 >> SM2Field29.Bits);
		Vector128<ulong> f7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(h7, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(f7, f7);
		Vector128<ulong> b7 = High(f7, f7) + Vector128.Create(SM2Field29.FourP7) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 7);
		Vector128<ulong> r7 = (b7 & Vector128.Create(SM2Field29.Mask)) + (b6 >> SM2Field29.Bits);
		Vector128<ulong> f8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(h8, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(f8, f8);
		Vector128<ulong> b8 = High(f8, f8) + Vector128.Create(SM2Field29.FourP8) - Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 8);
		Vector128<ulong> r8 = b8 + (b7 >> SM2Field29.Bits);
		TField.Multiply(in left, in right, out TField cubes);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(r0, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(r0, h0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(r1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(r1, h1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(r2, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(r2, h2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(r3, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(r3, h3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(r4, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(r4, h4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(r5, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(r5, h5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(r6, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(r6, h6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(r7, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(r7, h7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(r8, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(r8, h8);
		TField.Multiply(in left, in right, out products);
		Vector128<ulong> g0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 0);
		Vector128<ulong> v0 = High(g0, g0);
		Vector128<ulong> j0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Vector128<ulong> x0 = j0 + Vector128.Create(3 * SM2Field29.FourP0) - g0 - (v0 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 0) = Low(x0, x0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Low(r0, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(v0 + (v0 << 1) + g0 + Vector128.Create(SM2Field29.FourP0) - j0, g0);
		Vector128<ulong> g1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 1);
		Vector128<ulong> v1 = High(g1, g1);
		Vector128<ulong> j1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Vector128<ulong> x1 = j1 + Vector128.Create(3 * SM2Field29.FourP1) - g1 - (v1 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 1) = Low(x1, x1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Low(r1, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(v1 + (v1 << 1) + g1 + Vector128.Create(SM2Field29.FourP1) - j1, g1);
		Vector128<ulong> g2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 2);
		Vector128<ulong> v2 = High(g2, g2);
		Vector128<ulong> j2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Vector128<ulong> x2 = j2 + Vector128.Create(3 * SM2Field29.FourP2) - g2 - (v2 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 2) = Low(x2, x2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Low(r2, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(v2 + (v2 << 1) + g2 + Vector128.Create(SM2Field29.FourP2) - j2, g2);
		Vector128<ulong> g3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 3);
		Vector128<ulong> v3 = High(g3, g3);
		Vector128<ulong> j3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Vector128<ulong> x3 = j3 + Vector128.Create(3 * SM2Field29.FourP3) - g3 - (v3 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 3) = Low(x3, x3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Low(r3, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(v3 + (v3 << 1) + g3 + Vector128.Create(SM2Field29.FourP3) - j3, g3);
		Vector128<ulong> g4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 4);
		Vector128<ulong> v4 = High(g4, g4);
		Vector128<ulong> j4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Vector128<ulong> x4 = j4 + Vector128.Create(3 * SM2Field29.FourPMiddle) - g4 - (v4 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 4) = Low(x4, x4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Low(r4, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(v4 + (v4 << 1) + g4 + Vector128.Create(SM2Field29.FourPMiddle) - j4, g4);
		Vector128<ulong> g5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 5);
		Vector128<ulong> v5 = High(g5, g5);
		Vector128<ulong> j5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Vector128<ulong> x5 = j5 + Vector128.Create(3 * SM2Field29.FourPMiddle) - g5 - (v5 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 5) = Low(x5, x5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Low(r5, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(v5 + (v5 << 1) + g5 + Vector128.Create(SM2Field29.FourPMiddle) - j5, g5);
		Vector128<ulong> g6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 6);
		Vector128<ulong> v6 = High(g6, g6);
		Vector128<ulong> j6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Vector128<ulong> x6 = j6 + Vector128.Create(3 * SM2Field29.FourPMiddle) - g6 - (v6 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 6) = Low(x6, x6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Low(r6, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(v6 + (v6 << 1) + g6 + Vector128.Create(SM2Field29.FourPMiddle) - j6, g6);
		Vector128<ulong> g7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 7);
		Vector128<ulong> v7 = High(g7, g7);
		Vector128<ulong> j7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Vector128<ulong> x7 = j7 + Vector128.Create(3 * SM2Field29.FourP7) - g7 - (v7 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 7) = Low(x7, x7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Low(r7, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(v7 + (v7 << 1) + g7 + Vector128.Create(SM2Field29.FourP7) - j7, g7);
		Vector128<ulong> g8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 8);
		Vector128<ulong> v8 = High(g8, g8);
		Vector128<ulong> j8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Vector128<ulong> x8 = j8 + Vector128.Create(3 * SM2Field29.FourP8) - g8 - (v8 << 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref xs), 8) = Low(x8, x8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Low(r8, Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref first), 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(v8 + (v8 << 1) + g8 + Vector128.Create(SM2Field29.FourP8) - j8, g8);
		TField.Reduce(in xs, out result.XX);
		TField.Multiply(in left, in right, out cubes);
		Vector128<ulong> w0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(w0 + Vector128.Create(SM2Field29.FourP0) - High(w0, w0), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0));
		Vector128<ulong> w1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(w1 + Vector128.Create(SM2Field29.FourP1) - High(w1, w1), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1));
		Vector128<ulong> w2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(w2 + Vector128.Create(SM2Field29.FourP2) - High(w2, w2), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2));
		Vector128<ulong> w3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(w3 + Vector128.Create(SM2Field29.FourP3) - High(w3, w3), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3));
		Vector128<ulong> w4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(w4 + Vector128.Create(SM2Field29.FourPMiddle) - High(w4, w4), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4));
		Vector128<ulong> w5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(w5 + Vector128.Create(SM2Field29.FourPMiddle) - High(w5, w5), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5));
		Vector128<ulong> w6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(w6 + Vector128.Create(SM2Field29.FourPMiddle) - High(w6, w6), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6));
		Vector128<ulong> w7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(w7 + Vector128.Create(SM2Field29.FourP7) - High(w7, w7), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7));
		Vector128<ulong> w8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(w8 + Vector128.Create(SM2Field29.FourP8) - High(w8, w8), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8));
		TField.Reduce(in left, out result.YZ);
	}

	// point + (x2, y2) for an affine [x2 | y2] neither equal nor opposite to the point, and neither of them the point at infinity, with the formulas of Add for Z2 = 1, Y1 as Reduce leaves it: [Z1² | y2·Z1], [U2 | S2] = [x2·Z1² | y2·Z1·Z1²], [H² | R²] = [H·H | R·R] for [H | R] = [U2 − X1 | S2 − Y1], [H³ | V] = [H·H² | X1·H²] and [R·(V − X3) | Y1·H³], and Z3 = Z1·H, which needs only H, so that the rounds after it can overlap it. [H | R] + 4p, in limbs below 3·2^29 + 2^6, goes into the products carried, in limbs below 2^29 + 3, but for Z1·H; V − X3 + 4p has limbs below 6·2^29 + 2^8, X3 + 12p limbs below 7·2^29 + 2^6 and Y3 + 4p limbs below 3·2^29 + 2^6.
	[SkipLocalsInit]
	internal static void AddAffine(ref SM2PairPoint<TField> point, in TField affine)
	{
		Unsafe.SkipInit(out TField left);
		Unsafe.SkipInit(out TField right);
		Unsafe.SkipInit(out TField hr);
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		ref Vector128<ulong> xx = ref Limbs(in point.XX);
		ref Vector128<ulong> yz = ref Limbs(in point.YZ);
		ref Vector128<ulong> e = ref Limbs(in affine);
		Vector128<ulong> z0 = Unsafe.Add(ref yz, 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = High(z0, Unsafe.Add(ref e, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = High(z0, z0);
		Vector128<ulong> z1 = Unsafe.Add(ref yz, 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = High(z1, Unsafe.Add(ref e, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = High(z1, z1);
		Vector128<ulong> z2 = Unsafe.Add(ref yz, 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = High(z2, Unsafe.Add(ref e, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = High(z2, z2);
		Vector128<ulong> z3 = Unsafe.Add(ref yz, 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = High(z3, Unsafe.Add(ref e, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = High(z3, z3);
		Vector128<ulong> z4 = Unsafe.Add(ref yz, 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = High(z4, Unsafe.Add(ref e, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = High(z4, z4);
		Vector128<ulong> z5 = Unsafe.Add(ref yz, 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = High(z5, Unsafe.Add(ref e, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = High(z5, z5);
		Vector128<ulong> z6 = Unsafe.Add(ref yz, 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = High(z6, Unsafe.Add(ref e, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = High(z6, z6);
		Vector128<ulong> z7 = Unsafe.Add(ref yz, 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = High(z7, Unsafe.Add(ref e, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = High(z7, z7);
		Vector128<ulong> z8 = Unsafe.Add(ref yz, 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = High(z8, Unsafe.Add(ref e, 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = High(z8, z8);
		TField.Multiply(in left, in right, out TField squares);
		Vector128<ulong> a0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(Unsafe.Add(ref e, 0), a0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(a0, a0);
		Vector128<ulong> a1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(Unsafe.Add(ref e, 1), a1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(a1, a1);
		Vector128<ulong> a2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(Unsafe.Add(ref e, 2), a2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(a2, a2);
		Vector128<ulong> a3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(Unsafe.Add(ref e, 3), a3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(a3, a3);
		Vector128<ulong> a4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(Unsafe.Add(ref e, 4), a4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(a4, a4);
		Vector128<ulong> a5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(Unsafe.Add(ref e, 5), a5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(a5, a5);
		Vector128<ulong> a6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(Unsafe.Add(ref e, 6), a6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(a6, a6);
		Vector128<ulong> a7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(Unsafe.Add(ref e, 7), a7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(a7, a7);
		Vector128<ulong> a8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(Unsafe.Add(ref e, 8), a8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(a8, a8);
		TField.Multiply(in left, in right, out TField products);
		// [H | R] carried.
		Vector128<ulong> u0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0) + Vector128.Create(SM2Field29.FourP0) - Low(Unsafe.Add(ref xx, 0), Unsafe.Add(ref yz, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 0) = u0 & mask;
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = High(Unsafe.Add(ref yz, 0), Unsafe.Add(ref yz, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(u0, u0);
		Vector128<ulong> u1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1) + Vector128.Create(SM2Field29.FourP1) - Low(Unsafe.Add(ref xx, 1), Unsafe.Add(ref yz, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 1) = (u1 & mask) + (u0 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = High(Unsafe.Add(ref yz, 1), Unsafe.Add(ref yz, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(u1, u1);
		Vector128<ulong> u2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2) + Vector128.Create(SM2Field29.FourP2) - Low(Unsafe.Add(ref xx, 2), Unsafe.Add(ref yz, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 2) = (u2 & mask) + (u1 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = High(Unsafe.Add(ref yz, 2), Unsafe.Add(ref yz, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(u2, u2);
		Vector128<ulong> u3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3) + Vector128.Create(SM2Field29.FourP3) - Low(Unsafe.Add(ref xx, 3), Unsafe.Add(ref yz, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 3) = (u3 & mask) + (u2 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = High(Unsafe.Add(ref yz, 3), Unsafe.Add(ref yz, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(u3, u3);
		Vector128<ulong> u4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4) + Vector128.Create(SM2Field29.FourPMiddle) - Low(Unsafe.Add(ref xx, 4), Unsafe.Add(ref yz, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 4) = (u4 & mask) + (u3 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = High(Unsafe.Add(ref yz, 4), Unsafe.Add(ref yz, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(u4, u4);
		Vector128<ulong> u5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5) + Vector128.Create(SM2Field29.FourPMiddle) - Low(Unsafe.Add(ref xx, 5), Unsafe.Add(ref yz, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 5) = (u5 & mask) + (u4 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = High(Unsafe.Add(ref yz, 5), Unsafe.Add(ref yz, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(u5, u5);
		Vector128<ulong> u6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6) + Vector128.Create(SM2Field29.FourPMiddle) - Low(Unsafe.Add(ref xx, 6), Unsafe.Add(ref yz, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 6) = (u6 & mask) + (u5 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = High(Unsafe.Add(ref yz, 6), Unsafe.Add(ref yz, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(u6, u6);
		Vector128<ulong> u7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7) + Vector128.Create(SM2Field29.FourP7) - Low(Unsafe.Add(ref xx, 7), Unsafe.Add(ref yz, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 7) = (u7 & mask) + (u6 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = High(Unsafe.Add(ref yz, 7), Unsafe.Add(ref yz, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(u7, u7);
		Vector128<ulong> u8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8) + Vector128.Create(SM2Field29.FourP8) - Low(Unsafe.Add(ref xx, 8), Unsafe.Add(ref yz, 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 8) = u8 + (u7 >> SM2Field29.Bits);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = High(Unsafe.Add(ref yz, 8), Unsafe.Add(ref yz, 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(u8, u8);
		TField.Multiply(in left, in right, out TField zh);
		TField.Square(in hr, out squares);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 0), Unsafe.Add(ref xx, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 1), Unsafe.Add(ref xx, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 2), Unsafe.Add(ref xx, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 3), Unsafe.Add(ref xx, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 4), Unsafe.Add(ref xx, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 5), Unsafe.Add(ref xx, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 6), Unsafe.Add(ref xx, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 7), Unsafe.Add(ref xx, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 8), Unsafe.Add(ref xx, 8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = Low(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8));
		TField.Multiply(in left, in right, out products);
		Vector128<ulong> s0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0);
		Vector128<ulong> g0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Vector128<ulong> h0 = Low(g0, g0);
		Vector128<ulong> x0 = s0 + Vector128.Create(3 * SM2Field29.FourP0) - h0 - (g0 << 1);
		Vector128<ulong> y0 = Unsafe.Add(ref yz, 0);
		Unsafe.Add(ref xx, 0) = High(x0, x0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 0), Low(y0, y0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 0) = High(g0 + (g0 << 1) + h0 + Vector128.Create(SM2Field29.FourP0) - s0, h0);
		Vector128<ulong> s1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1);
		Vector128<ulong> g1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Vector128<ulong> h1 = Low(g1, g1);
		Vector128<ulong> x1 = s1 + Vector128.Create(3 * SM2Field29.FourP1) - h1 - (g1 << 1);
		Vector128<ulong> y1 = Unsafe.Add(ref yz, 1);
		Unsafe.Add(ref xx, 1) = High(x1, x1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 1), Low(y1, y1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 1) = High(g1 + (g1 << 1) + h1 + Vector128.Create(SM2Field29.FourP1) - s1, h1);
		Vector128<ulong> s2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2);
		Vector128<ulong> g2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Vector128<ulong> h2 = Low(g2, g2);
		Vector128<ulong> x2 = s2 + Vector128.Create(3 * SM2Field29.FourP2) - h2 - (g2 << 1);
		Vector128<ulong> y2 = Unsafe.Add(ref yz, 2);
		Unsafe.Add(ref xx, 2) = High(x2, x2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 2), Low(y2, y2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 2) = High(g2 + (g2 << 1) + h2 + Vector128.Create(SM2Field29.FourP2) - s2, h2);
		Vector128<ulong> s3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3);
		Vector128<ulong> g3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Vector128<ulong> h3 = Low(g3, g3);
		Vector128<ulong> x3 = s3 + Vector128.Create(3 * SM2Field29.FourP3) - h3 - (g3 << 1);
		Vector128<ulong> y3 = Unsafe.Add(ref yz, 3);
		Unsafe.Add(ref xx, 3) = High(x3, x3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 3), Low(y3, y3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 3) = High(g3 + (g3 << 1) + h3 + Vector128.Create(SM2Field29.FourP3) - s3, h3);
		Vector128<ulong> s4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4);
		Vector128<ulong> g4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Vector128<ulong> h4 = Low(g4, g4);
		Vector128<ulong> x4 = s4 + Vector128.Create(3 * SM2Field29.FourPMiddle) - h4 - (g4 << 1);
		Vector128<ulong> y4 = Unsafe.Add(ref yz, 4);
		Unsafe.Add(ref xx, 4) = High(x4, x4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 4), Low(y4, y4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 4) = High(g4 + (g4 << 1) + h4 + Vector128.Create(SM2Field29.FourPMiddle) - s4, h4);
		Vector128<ulong> s5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5);
		Vector128<ulong> g5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Vector128<ulong> h5 = Low(g5, g5);
		Vector128<ulong> x5 = s5 + Vector128.Create(3 * SM2Field29.FourPMiddle) - h5 - (g5 << 1);
		Vector128<ulong> y5 = Unsafe.Add(ref yz, 5);
		Unsafe.Add(ref xx, 5) = High(x5, x5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 5), Low(y5, y5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 5) = High(g5 + (g5 << 1) + h5 + Vector128.Create(SM2Field29.FourPMiddle) - s5, h5);
		Vector128<ulong> s6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6);
		Vector128<ulong> g6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Vector128<ulong> h6 = Low(g6, g6);
		Vector128<ulong> x6 = s6 + Vector128.Create(3 * SM2Field29.FourPMiddle) - h6 - (g6 << 1);
		Vector128<ulong> y6 = Unsafe.Add(ref yz, 6);
		Unsafe.Add(ref xx, 6) = High(x6, x6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 6), Low(y6, y6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 6) = High(g6 + (g6 << 1) + h6 + Vector128.Create(SM2Field29.FourPMiddle) - s6, h6);
		Vector128<ulong> s7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7);
		Vector128<ulong> g7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Vector128<ulong> h7 = Low(g7, g7);
		Vector128<ulong> x7 = s7 + Vector128.Create(3 * SM2Field29.FourP7) - h7 - (g7 << 1);
		Vector128<ulong> y7 = Unsafe.Add(ref yz, 7);
		Unsafe.Add(ref xx, 7) = High(x7, x7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 7), Low(y7, y7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 7) = High(g7 + (g7 << 1) + h7 + Vector128.Create(SM2Field29.FourP7) - s7, h7);
		Vector128<ulong> s8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8);
		Vector128<ulong> g8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Vector128<ulong> h8 = Low(g8, g8);
		Vector128<ulong> x8 = s8 + Vector128.Create(3 * SM2Field29.FourP8) - h8 - (g8 << 1);
		Vector128<ulong> y8 = Unsafe.Add(ref yz, 8);
		Unsafe.Add(ref xx, 8) = High(x8, x8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = High(Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref hr), 8), Low(y8, y8));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref right), 8) = High(g8 + (g8 << 1) + h8 + Vector128.Create(SM2Field29.FourP8) - s8, h8);
		TField.Reduce(in point.XX, out point.XX);
		TField.Multiply(in left, in right, out products);
		Vector128<ulong> w0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 0);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 0) = Blend(w0 + Vector128.Create(SM2Field29.FourP0) - High(w0, w0), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 0));
		Vector128<ulong> w1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 1);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 1) = Blend(w1 + Vector128.Create(SM2Field29.FourP1) - High(w1, w1), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 1));
		Vector128<ulong> w2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 2);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 2) = Blend(w2 + Vector128.Create(SM2Field29.FourP2) - High(w2, w2), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 2));
		Vector128<ulong> w3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 3);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 3) = Blend(w3 + Vector128.Create(SM2Field29.FourP3) - High(w3, w3), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 3));
		Vector128<ulong> w4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 4);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 4) = Blend(w4 + Vector128.Create(SM2Field29.FourPMiddle) - High(w4, w4), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 4));
		Vector128<ulong> w5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 5);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 5) = Blend(w5 + Vector128.Create(SM2Field29.FourPMiddle) - High(w5, w5), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 5));
		Vector128<ulong> w6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 6);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 6) = Blend(w6 + Vector128.Create(SM2Field29.FourPMiddle) - High(w6, w6), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 6));
		Vector128<ulong> w7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 7);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 7) = Blend(w7 + Vector128.Create(SM2Field29.FourP7) - High(w7, w7), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 7));
		Vector128<ulong> w8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref products), 8);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref left), 8) = Blend(w8 + Vector128.Create(SM2Field29.FourP8) - High(w8, w8), Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref zh), 8));
		TField.Reduce(in left, out point.YZ);
	}

	// Writes j·P to entry j − 1 of the table: 2j·P = 2·(j·P) and (2j + 1)·P = 2j·P + P, an addition of points neither equal nor opposite, as 2j ± 1 < n. Only 1·P to 8·P stay as points, for the doublings: each pair 2j·P and (2j + 1)·P goes into the table as it comes, and 16·P with P.
	[SkipLocalsInit]
	internal static void BuildTable(in AffinePoint<SM2Field52> point, Span<ulong> table)
	{
		const int kept = TableLength / 2;
		Span<SM2PairPoint<TField>> multiples = stackalloc SM2PairPoint<TField>[kept + 2];
		Span<SM2PairEntry<TField>> entries = stackalloc SM2PairEntry<TField>[2];
		ref SM2PairPoint<TField> even = ref multiples[kept];
		ref SM2PairPoint<TField> odd = ref multiples[kept + 1];
		FromAffine(in point, out TField affine);
		ToPoint(in affine, out multiples[0]);

		for (int j = 2; j < TableLength; j += 2)
		{
			Double(in multiples[j / 2 - 1], out even);
			odd = even;
			AddAffine(ref odd, in affine);

			if (j <= kept)
			{
				multiples[j - 1] = even;
			}

			if (j < kept)
			{
				multiples[j] = odd;
			}

			ToEntries(in even, in odd, out entries[0], out entries[1]);
			Pack(in entries[0], ref table[(j - 1) * EntryLength]);
			Pack(in entries[1], ref table[j * EntryLength]);
		}

		Double(in multiples[kept - 1], out even);
		ToEntries(in multiples[0], in even, out entries[0], out entries[1]);
		Pack(in entries[0], ref table[0]);
		Pack(in entries[1], ref table[(TableLength - 1) * EntryLength]);
		multiples.ZeroMemory();
		entries.ZeroMemory();
		affine.ZeroMemory();
	}

	// Sets bases[i] to 2^(wi)·P for w = width, each through ToJacobian, from one chain of doublings on the lanes; no base is the point at infinity, as 2^(wi) is no multiple of n. P is public, so nothing is cleared.
	internal static void FillBases(in AffinePoint<SM2Field52> point, int width, Span<JacobianPoint<SM2Field52>> bases)
	{
		FromAffine(in point, out TField affine);
		ToPoint(in affine, out SM2PairPoint<TField> total);
		JacobianPoint<SM2Field52>.FromAffine(in point, out bases[0]);

		for (int i = 1; i < bases.Length; ++i)
		{
			for (int k = 0; k < width; ++k)
			{
				Double(in total, out total);
			}

			ToJacobian(in total, out bases[i]);
		}
	}

	// Q, 3Q, …, 15Q: 3Q = 2Q + Q and (j + 2)·Q = j·Q + 2Q, additions of points neither equal nor opposite, as j + 2 < n.
	[SkipLocalsInit]
	internal static void BuildOddMultiples(in AffinePoint<SM2Field52> point, Span<SM2PairEntry<TField>> entries)
	{
		Span<SM2PairPoint<TField>> sums = stackalloc SM2PairPoint<TField>[OddLength];
		FromAffine(in point, out TField affine);
		ToPoint(in affine, out sums[0]);
		Double(in sums[0], out SM2PairPoint<TField> twice);
		ToEntries(in sums[0], in twice, out entries[0], out SM2PairEntry<TField> step);
		sums[1] = twice;
		AddAffine(ref sums[1], in affine);

		for (int j = 2; j < OddLength; ++j)
		{
			Add(in sums[j - 1], in step, out sums[j]);
		}

		for (int j = 1; j < OddLength - 1; j += 2)
		{
			ToEntries(in sums[j], in sums[j + 1], out entries[j], out entries[j + 1]);
		}

		ToEntries(in sums[OddLength - 1], in sums[OddLength - 1], out entries[OddLength - 1], out _);
	}

	// The entries of two points, Z² and Z³ of both from one product each.
	[SkipLocalsInit]
	private static void ToEntries(in SM2PairPoint<TField> low, in SM2PairPoint<TField> high, out SM2PairEntry<TField> lowEntry, out SM2PairEntry<TField> highEntry)
	{
		Unsafe.SkipInit(out TField z);
		Unsafe.SkipInit(out lowEntry);
		Unsafe.SkipInit(out highEntry);
		ref Vector128<ulong> lx = ref Limbs(in low.XX);
		ref Vector128<ulong> ly = ref Limbs(in low.YZ);
		ref Vector128<ulong> hx = ref Limbs(in high.XX);
		ref Vector128<ulong> hy = ref Limbs(in high.YZ);
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 0) = High(Unsafe.Add(ref ly, 0), Unsafe.Add(ref hy, 0));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 1) = High(Unsafe.Add(ref ly, 1), Unsafe.Add(ref hy, 1));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 2) = High(Unsafe.Add(ref ly, 2), Unsafe.Add(ref hy, 2));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 3) = High(Unsafe.Add(ref ly, 3), Unsafe.Add(ref hy, 3));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 4) = High(Unsafe.Add(ref ly, 4), Unsafe.Add(ref hy, 4));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 5) = High(Unsafe.Add(ref ly, 5), Unsafe.Add(ref hy, 5));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 6) = High(Unsafe.Add(ref ly, 6), Unsafe.Add(ref hy, 6));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 7) = High(Unsafe.Add(ref ly, 7), Unsafe.Add(ref hy, 7));
		Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref z), 8) = High(Unsafe.Add(ref ly, 8), Unsafe.Add(ref hy, 8));
		TField.Square(in z, out TField squares);
		TField.Multiply(in z, in squares, out TField cubes);
		ref Vector128<ulong> lxy = ref Limbs(in lowEntry.XY);
		ref Vector128<ulong> lc = ref Limbs(in lowEntry.CubeZ);
		ref Vector128<ulong> ls = ref Limbs(in lowEntry.SquareZ);
		ref Vector128<ulong> hxy = ref Limbs(in highEntry.XY);
		ref Vector128<ulong> hc = ref Limbs(in highEntry.CubeZ);
		ref Vector128<ulong> hs = ref Limbs(in highEntry.SquareZ);
		Vector128<ulong> l0 = Unsafe.Add(ref ly, 0);
		Vector128<ulong> h0 = Unsafe.Add(ref hy, 0);
		Vector128<ulong> lxx0 = Unsafe.Add(ref lx, 0);
		Vector128<ulong> hxx0 = Unsafe.Add(ref hx, 0);
		Vector128<ulong> c0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 0);
		Vector128<ulong> s0 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 0);
		Unsafe.Add(ref lxy, 0) = Low(lxx0, l0);
		Unsafe.Add(ref lc, 0) = Low(c0, High(l0, l0));
		Unsafe.Add(ref ls, 0) = s0;
		Unsafe.Add(ref hxy, 0) = Low(hxx0, h0);
		Unsafe.Add(ref hc, 0) = High(c0, h0);
		Unsafe.Add(ref hs, 0) = High(s0, s0);
		Vector128<ulong> l1 = Unsafe.Add(ref ly, 1);
		Vector128<ulong> h1 = Unsafe.Add(ref hy, 1);
		Vector128<ulong> lxx1 = Unsafe.Add(ref lx, 1);
		Vector128<ulong> hxx1 = Unsafe.Add(ref hx, 1);
		Vector128<ulong> c1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 1);
		Vector128<ulong> s1 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 1);
		Unsafe.Add(ref lxy, 1) = Low(lxx1, l1);
		Unsafe.Add(ref lc, 1) = Low(c1, High(l1, l1));
		Unsafe.Add(ref ls, 1) = s1;
		Unsafe.Add(ref hxy, 1) = Low(hxx1, h1);
		Unsafe.Add(ref hc, 1) = High(c1, h1);
		Unsafe.Add(ref hs, 1) = High(s1, s1);
		Vector128<ulong> l2 = Unsafe.Add(ref ly, 2);
		Vector128<ulong> h2 = Unsafe.Add(ref hy, 2);
		Vector128<ulong> lxx2 = Unsafe.Add(ref lx, 2);
		Vector128<ulong> hxx2 = Unsafe.Add(ref hx, 2);
		Vector128<ulong> c2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 2);
		Vector128<ulong> s2 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 2);
		Unsafe.Add(ref lxy, 2) = Low(lxx2, l2);
		Unsafe.Add(ref lc, 2) = Low(c2, High(l2, l2));
		Unsafe.Add(ref ls, 2) = s2;
		Unsafe.Add(ref hxy, 2) = Low(hxx2, h2);
		Unsafe.Add(ref hc, 2) = High(c2, h2);
		Unsafe.Add(ref hs, 2) = High(s2, s2);
		Vector128<ulong> l3 = Unsafe.Add(ref ly, 3);
		Vector128<ulong> h3 = Unsafe.Add(ref hy, 3);
		Vector128<ulong> lxx3 = Unsafe.Add(ref lx, 3);
		Vector128<ulong> hxx3 = Unsafe.Add(ref hx, 3);
		Vector128<ulong> c3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 3);
		Vector128<ulong> s3 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 3);
		Unsafe.Add(ref lxy, 3) = Low(lxx3, l3);
		Unsafe.Add(ref lc, 3) = Low(c3, High(l3, l3));
		Unsafe.Add(ref ls, 3) = s3;
		Unsafe.Add(ref hxy, 3) = Low(hxx3, h3);
		Unsafe.Add(ref hc, 3) = High(c3, h3);
		Unsafe.Add(ref hs, 3) = High(s3, s3);
		Vector128<ulong> l4 = Unsafe.Add(ref ly, 4);
		Vector128<ulong> h4 = Unsafe.Add(ref hy, 4);
		Vector128<ulong> lxx4 = Unsafe.Add(ref lx, 4);
		Vector128<ulong> hxx4 = Unsafe.Add(ref hx, 4);
		Vector128<ulong> c4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 4);
		Vector128<ulong> s4 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 4);
		Unsafe.Add(ref lxy, 4) = Low(lxx4, l4);
		Unsafe.Add(ref lc, 4) = Low(c4, High(l4, l4));
		Unsafe.Add(ref ls, 4) = s4;
		Unsafe.Add(ref hxy, 4) = Low(hxx4, h4);
		Unsafe.Add(ref hc, 4) = High(c4, h4);
		Unsafe.Add(ref hs, 4) = High(s4, s4);
		Vector128<ulong> l5 = Unsafe.Add(ref ly, 5);
		Vector128<ulong> h5 = Unsafe.Add(ref hy, 5);
		Vector128<ulong> lxx5 = Unsafe.Add(ref lx, 5);
		Vector128<ulong> hxx5 = Unsafe.Add(ref hx, 5);
		Vector128<ulong> c5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 5);
		Vector128<ulong> s5 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 5);
		Unsafe.Add(ref lxy, 5) = Low(lxx5, l5);
		Unsafe.Add(ref lc, 5) = Low(c5, High(l5, l5));
		Unsafe.Add(ref ls, 5) = s5;
		Unsafe.Add(ref hxy, 5) = Low(hxx5, h5);
		Unsafe.Add(ref hc, 5) = High(c5, h5);
		Unsafe.Add(ref hs, 5) = High(s5, s5);
		Vector128<ulong> l6 = Unsafe.Add(ref ly, 6);
		Vector128<ulong> h6 = Unsafe.Add(ref hy, 6);
		Vector128<ulong> lxx6 = Unsafe.Add(ref lx, 6);
		Vector128<ulong> hxx6 = Unsafe.Add(ref hx, 6);
		Vector128<ulong> c6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 6);
		Vector128<ulong> s6 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 6);
		Unsafe.Add(ref lxy, 6) = Low(lxx6, l6);
		Unsafe.Add(ref lc, 6) = Low(c6, High(l6, l6));
		Unsafe.Add(ref ls, 6) = s6;
		Unsafe.Add(ref hxy, 6) = Low(hxx6, h6);
		Unsafe.Add(ref hc, 6) = High(c6, h6);
		Unsafe.Add(ref hs, 6) = High(s6, s6);
		Vector128<ulong> l7 = Unsafe.Add(ref ly, 7);
		Vector128<ulong> h7 = Unsafe.Add(ref hy, 7);
		Vector128<ulong> lxx7 = Unsafe.Add(ref lx, 7);
		Vector128<ulong> hxx7 = Unsafe.Add(ref hx, 7);
		Vector128<ulong> c7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 7);
		Vector128<ulong> s7 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 7);
		Unsafe.Add(ref lxy, 7) = Low(lxx7, l7);
		Unsafe.Add(ref lc, 7) = Low(c7, High(l7, l7));
		Unsafe.Add(ref ls, 7) = s7;
		Unsafe.Add(ref hxy, 7) = Low(hxx7, h7);
		Unsafe.Add(ref hc, 7) = High(c7, h7);
		Unsafe.Add(ref hs, 7) = High(s7, s7);
		Vector128<ulong> l8 = Unsafe.Add(ref ly, 8);
		Vector128<ulong> h8 = Unsafe.Add(ref hy, 8);
		Vector128<ulong> lxx8 = Unsafe.Add(ref lx, 8);
		Vector128<ulong> hxx8 = Unsafe.Add(ref hx, 8);
		Vector128<ulong> c8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref cubes), 8);
		Vector128<ulong> s8 = Unsafe.Add(ref Unsafe.As<TField, Vector128<ulong>>(ref squares), 8);
		Unsafe.Add(ref lxy, 8) = Low(lxx8, l8);
		Unsafe.Add(ref lc, 8) = Low(c8, High(l8, l8));
		Unsafe.Add(ref ls, 8) = s8;
		Unsafe.Add(ref hxy, 8) = Low(hxx8, h8);
		Unsafe.Add(ref hc, 8) = High(c8, h8);
		Unsafe.Add(ref hs, 8) = High(s8, s8);
	}

	// An entry in EntryLength limbs at destination.
	private static void Pack(in SM2PairEntry<TField> entry, ref ulong destination)
	{
		ref Vector128<ulong> xy = ref Limbs(in entry.XY);
		ref Vector128<ulong> c = ref Limbs(in entry.CubeZ);
		ref Vector128<ulong> s = ref Limbs(in entry.SquareZ);
		Join(Unsafe.Add(ref xy, 0), Unsafe.Add(ref xy, 1)).StoreUnsafe(ref destination, 0);
		Join(Unsafe.Add(ref c, 0), Unsafe.Add(ref c, 1)).StoreUnsafe(ref destination, CubeOffset + 0);
		Unsafe.Add(ref destination, SquareOffset + 0) = Join(Unsafe.Add(ref s, 0), Unsafe.Add(ref s, 1)).ToScalar();
		Join(Unsafe.Add(ref xy, 2), Unsafe.Add(ref xy, 3)).StoreUnsafe(ref destination, 2);
		Join(Unsafe.Add(ref c, 2), Unsafe.Add(ref c, 3)).StoreUnsafe(ref destination, CubeOffset + 2);
		Unsafe.Add(ref destination, SquareOffset + 1) = Join(Unsafe.Add(ref s, 2), Unsafe.Add(ref s, 3)).ToScalar();
		Join(Unsafe.Add(ref xy, 4), Unsafe.Add(ref xy, 5)).StoreUnsafe(ref destination, 4);
		Join(Unsafe.Add(ref c, 4), Unsafe.Add(ref c, 5)).StoreUnsafe(ref destination, CubeOffset + 4);
		Unsafe.Add(ref destination, SquareOffset + 2) = Join(Unsafe.Add(ref s, 4), Unsafe.Add(ref s, 5)).ToScalar();
		Join(Unsafe.Add(ref xy, 6), Unsafe.Add(ref xy, 7)).StoreUnsafe(ref destination, 6);
		Join(Unsafe.Add(ref c, 6), Unsafe.Add(ref c, 7)).StoreUnsafe(ref destination, CubeOffset + 6);
		Unsafe.Add(ref destination, SquareOffset + 3) = Join(Unsafe.Add(ref s, 6), Unsafe.Add(ref s, 7)).ToScalar();
		Unsafe.Add(ref xy, 8).StoreUnsafe(ref destination, 8);
		Unsafe.Add(ref c, 8).StoreUnsafe(ref destination, CubeOffset + 8);
		Unsafe.Add(ref destination, SquareOffset + 4) = Unsafe.Add(ref s, 8).ToScalar();
	}

	// The entry of digit, read by a masked scan of the table, with Y negated for a digit below 0; a digit of 0 gives zeros, which the masks discard.
	private static void Select(ReadOnlySpan<ulong> table, int digit, Span<ulong> packed, Span<ulong> negative, out SM2PairEntry<TField> entry)
	{
		int sign = digit >> 31;
		MaskedSelect.Lookup(in table[0], EntryLength, TableLength, (uint)((digit ^ sign) - sign) - 1, ref packed[0]);
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		ref ulong source = ref packed[0];
		Unsafe.SkipInit(out entry);
		ref Vector128<ulong> xy = ref Limbs(in entry.XY);
		ref Vector128<ulong> c = ref Limbs(in entry.CubeZ);
		ref Vector128<ulong> s = ref Limbs(in entry.SquareZ);
		Vector128<ulong> xy0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<ulong> cube0 = Vector128.LoadUnsafe(ref source, CubeOffset + 0);
		Vector128<ulong> square0 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 0));
		Unsafe.Add(ref xy, 0) = xy0 & mask;
		Unsafe.Add(ref xy, 1) = xy0 >> SM2Field29.Bits;
		Unsafe.Add(ref c, 0) = cube0 & mask;
		Unsafe.Add(ref c, 1) = cube0 >> SM2Field29.Bits;
		Unsafe.Add(ref s, 0) = square0 & mask;
		Unsafe.Add(ref s, 1) = square0 >> SM2Field29.Bits;
		Vector128<ulong> xy2 = Vector128.LoadUnsafe(ref source, 2);
		Vector128<ulong> cube2 = Vector128.LoadUnsafe(ref source, CubeOffset + 2);
		Vector128<ulong> square2 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 1));
		Unsafe.Add(ref xy, 2) = xy2 & mask;
		Unsafe.Add(ref xy, 3) = xy2 >> SM2Field29.Bits;
		Unsafe.Add(ref c, 2) = cube2 & mask;
		Unsafe.Add(ref c, 3) = cube2 >> SM2Field29.Bits;
		Unsafe.Add(ref s, 2) = square2 & mask;
		Unsafe.Add(ref s, 3) = square2 >> SM2Field29.Bits;
		Vector128<ulong> xy4 = Vector128.LoadUnsafe(ref source, 4);
		Vector128<ulong> cube4 = Vector128.LoadUnsafe(ref source, CubeOffset + 4);
		Vector128<ulong> square4 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 2));
		Unsafe.Add(ref xy, 4) = xy4 & mask;
		Unsafe.Add(ref xy, 5) = xy4 >> SM2Field29.Bits;
		Unsafe.Add(ref c, 4) = cube4 & mask;
		Unsafe.Add(ref c, 5) = cube4 >> SM2Field29.Bits;
		Unsafe.Add(ref s, 4) = square4 & mask;
		Unsafe.Add(ref s, 5) = square4 >> SM2Field29.Bits;
		Vector128<ulong> xy6 = Vector128.LoadUnsafe(ref source, 6);
		Vector128<ulong> cube6 = Vector128.LoadUnsafe(ref source, CubeOffset + 6);
		Vector128<ulong> square6 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 3));
		Unsafe.Add(ref xy, 6) = xy6 & mask;
		Unsafe.Add(ref xy, 7) = xy6 >> SM2Field29.Bits;
		Unsafe.Add(ref c, 6) = cube6 & mask;
		Unsafe.Add(ref c, 7) = cube6 >> SM2Field29.Bits;
		Unsafe.Add(ref s, 6) = square6 & mask;
		Unsafe.Add(ref s, 7) = square6 >> SM2Field29.Bits;
		Unsafe.Add(ref xy, 8) = Vector128.LoadUnsafe(ref source, 8);
		Unsafe.Add(ref c, 8) = Vector128.LoadUnsafe(ref source, CubeOffset + 8);
		Unsafe.Add(ref s, 8) = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 4));
		// Y alone, in lane 1 of XY.
		negative[0] = 0;
		negative[1] = (ulong)sign;
		TField.ConditionalNegate(in negative[0], ref entry.XY);
	}

	// The point (X2, Y2, Z2) of an entry.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ToPoint(in SM2PairEntry<TField> entry, out SM2PairPoint<TField> result)
	{
		ToPoint(in entry.XY, in entry.CubeZ, out result);
	}

	// The point (x, y, 1) of an affine [x | y].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void ToPoint(in TField affine, out SM2PairPoint<TField> result)
	{
		TField.One(out TField one);
		ToPoint(in affine, in one, out result);
	}

	// z holds Z in its upper lane, as CubeZ and one do.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	[SkipLocalsInit]
	private static void ToPoint(in TField xy, in TField z, out SM2PairPoint<TField> result)
	{
		Unsafe.SkipInit(out result);
		ref Vector128<ulong> exy = ref Limbs(in xy);
		ref Vector128<ulong> ez = ref Limbs(in z);
		ref Vector128<ulong> xx = ref Limbs(in result.XX);
		ref Vector128<ulong> yz = ref Limbs(in result.YZ);
		Vector128<ulong> xy0 = Unsafe.Add(ref exy, 0);
		Unsafe.Add(ref xx, 0) = Low(xy0, xy0);
		Unsafe.Add(ref yz, 0) = High(xy0, Unsafe.Add(ref ez, 0));
		Vector128<ulong> xy1 = Unsafe.Add(ref exy, 1);
		Unsafe.Add(ref xx, 1) = Low(xy1, xy1);
		Unsafe.Add(ref yz, 1) = High(xy1, Unsafe.Add(ref ez, 1));
		Vector128<ulong> xy2 = Unsafe.Add(ref exy, 2);
		Unsafe.Add(ref xx, 2) = Low(xy2, xy2);
		Unsafe.Add(ref yz, 2) = High(xy2, Unsafe.Add(ref ez, 2));
		Vector128<ulong> xy3 = Unsafe.Add(ref exy, 3);
		Unsafe.Add(ref xx, 3) = Low(xy3, xy3);
		Unsafe.Add(ref yz, 3) = High(xy3, Unsafe.Add(ref ez, 3));
		Vector128<ulong> xy4 = Unsafe.Add(ref exy, 4);
		Unsafe.Add(ref xx, 4) = Low(xy4, xy4);
		Unsafe.Add(ref yz, 4) = High(xy4, Unsafe.Add(ref ez, 4));
		Vector128<ulong> xy5 = Unsafe.Add(ref exy, 5);
		Unsafe.Add(ref xx, 5) = Low(xy5, xy5);
		Unsafe.Add(ref yz, 5) = High(xy5, Unsafe.Add(ref ez, 5));
		Vector128<ulong> xy6 = Unsafe.Add(ref exy, 6);
		Unsafe.Add(ref xx, 6) = Low(xy6, xy6);
		Unsafe.Add(ref yz, 6) = High(xy6, Unsafe.Add(ref ez, 6));
		Vector128<ulong> xy7 = Unsafe.Add(ref exy, 7);
		Unsafe.Add(ref xx, 7) = Low(xy7, xy7);
		Unsafe.Add(ref yz, 7) = High(xy7, Unsafe.Add(ref ez, 7));
		Vector128<ulong> xy8 = Unsafe.Add(ref exy, 8);
		Unsafe.Add(ref xx, 8) = Low(xy8, xy8);
		Unsafe.Add(ref yz, 8) = High(xy8, Unsafe.Add(ref ez, 8));
	}

	// [x | y] for an affine point of the form E of SM2Field52, reduced: each coordinate a·2^260 as a·2^261, its limbs of radix 2^52 doubled and cut into limbs of radix 2^29, limbs 2m + 1 taking the bits of a limb of radix 2^52 that cross into the next as a sum, below 2^30, for Reduce.
	private static void FromAffine(in AffinePoint<SM2Field52> point, out TField result)
	{
		Unsafe.SkipInit(out result);
		Vector128<ulong> mask = Vector128.Create(SM2Field29.Mask);
		ref ulong x = ref Unsafe.As<SM2Field52, ulong>(ref Unsafe.AsRef(in point.X));
		ref ulong y = ref Unsafe.As<SM2Field52, ulong>(ref Unsafe.AsRef(in point.Y));
		ref Vector128<ulong> xy = ref Limbs(in result);
		Vector128<ulong> d0 = Vector128.Create(Unsafe.Add(ref x, 0), Unsafe.Add(ref y, 0)) << 1;
		Vector128<ulong> d1 = Vector128.Create(Unsafe.Add(ref x, 1), Unsafe.Add(ref y, 1)) << 1;
		Vector128<ulong> d2 = Vector128.Create(Unsafe.Add(ref x, 2), Unsafe.Add(ref y, 2)) << 1;
		Vector128<ulong> d3 = Vector128.Create(Unsafe.Add(ref x, 3), Unsafe.Add(ref y, 3)) << 1;
		Vector128<ulong> d4 = Vector128.Create(Unsafe.Add(ref x, 4), Unsafe.Add(ref y, 4)) << 1;
		Unsafe.Add(ref xy, 0) = d0 & mask;
		Unsafe.Add(ref xy, 1) = (d0 >> 29) + (d1 << 23 & mask);
		Unsafe.Add(ref xy, 2) = d1 >> 6 & mask;
		Unsafe.Add(ref xy, 3) = (d1 >> 35) + (d2 << 17 & mask);
		Unsafe.Add(ref xy, 4) = d2 >> 12 & mask;
		Unsafe.Add(ref xy, 5) = (d2 >> 41) + (d3 << 11 & mask);
		Unsafe.Add(ref xy, 6) = d3 >> 18 & mask;
		Unsafe.Add(ref xy, 7) = (d3 >> 47) + (d4 << 5 & mask);
		Unsafe.Add(ref xy, 8) = d4 >> 24;
		TField.Reduce(in result, out result);
	}

	// The point in the form E of SM2Field52, through Halve and Reduce.
	private static void ToJacobian(in SM2PairPoint<TField> point, out JacobianPoint<SM2Field52> result)
	{
		TField.Halve(in point.XX, out TField x);
		TField.Reduce(in x, out x);
		TField.Halve(in point.YZ, out TField yz);
		TField.Reduce(in yz, out yz);
		SM2Field29.ToField52(in x, 0, out result.X);
		SM2Field29.ToField52(in yz, 0, out result.Y);
		SM2Field29.ToField52(in yz, 1, out result.Z);
	}

	// The nine limbs of a value, each the vector of both lanes. The formulas write through it only to the values they own.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref Vector128<ulong> Limbs(in TField value)
	{
		return ref Unsafe.As<TField, Vector128<ulong>>(ref Unsafe.AsRef(in value));
	}

	// Limbs 2m and 2m + 1 as one ulong, limb 2m + 1 from bit 29 up; splitting it again gives the same value, limb 2m + 1 taking what limb 2m of a product holds from 2^29 up.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Join(Vector128<ulong> low, Vector128<ulong> high)
	{
		return low + (high << SM2Field29.Bits);
	}

	// [a.lo | b.lo].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Low(Vector128<ulong> a, Vector128<ulong> b)
	{
		return Vector128.ZipLower(a, b);
	}

	// [a.hi | b.hi].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> High(Vector128<ulong> a, Vector128<ulong> b)
	{
		return Vector128.ZipUpper(a, b);
	}

	// [b.hi | a.lo].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Cross(Vector128<ulong> a, Vector128<ulong> b)
	{
		return Ssse3.IsSupported ? Ssse3.AlignRight(a.AsByte(), b.AsByte(), 8).AsUInt64() : AdvSimd.ExtractVector128(b, a, 1);
	}

	// [a.lo | b.hi].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Blend(Vector128<ulong> a, Vector128<ulong> b)
	{
		return Sse41.IsSupported ? Sse41.Blend(a.AsUInt16(), b.AsUInt16(), 0xF0).AsUInt64() : AdvSimd.Arm64.InsertSelectedScalar(a, 1, b, 1);
	}
}

// A point of SM2PairFormulas: X in both lanes of XX, Y and Z in the lanes of YZ.
internal struct SM2PairPoint<TField> where TField : unmanaged, ISM2Field29Lanes<TField>
{
	internal TField XX;
	internal TField YZ;

	// mask is a lane mask; result may be either input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ref readonly ulong mask, in SM2PairPoint<TField> whenSet, in SM2PairPoint<TField> whenClear, out SM2PairPoint<TField> result)
	{
		TField.ConditionalSelect(in mask, in whenSet.XX, in whenClear.XX, out result.XX);
		TField.ConditionalSelect(in mask, in whenSet.YZ, in whenClear.YZ, out result.YZ);
	}
}

// An entry of SM2PairFormulas: XY = [X | Y], CubeZ = [Z³ | Z] and Z² in lane 0 of SquareZ.
internal struct SM2PairEntry<TField> where TField : unmanaged, ISM2Field29Lanes<TField>
{
	internal TField XY;
	internal TField CubeZ;
	internal TField SquareZ;
}
