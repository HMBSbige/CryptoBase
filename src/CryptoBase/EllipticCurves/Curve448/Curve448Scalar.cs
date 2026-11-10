namespace CryptoBase.EllipticCurves.Curve448;

// The kernel of Field448 alone, for every platform.
internal readonly struct Curve448Scalar : ICurve448Kernel
{
	// (A − 2)/4 for the Montgomery coefficient A = 156326.
	private const uint A24 = 39081;

	// The NAF width of the point in DoubleScalarMultiplyVariableTime.
	private const int PointWidth = 5;

	public static bool IsSupported => true;

	// Each step takes the bit of k from 447 down to 0. The swap mask is the XOR of the bit with the one before, so only arithmetic on k decides which pair each step doubles.
	[SkipLocalsInit]
	public static void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		ScalarDigits.ReadLimbs(scalar, limbs);
		Field448 x1 = u;
		Field448 x2 = Field448.One;
		Field448 z2 = default;
		Field448 x3 = u;
		Field448 z3 = Field448.One;
		ulong swap = 0;

		for (int t = 447; t >= 0; --t)
		{
			ulong bit = limbs[t >> 6] >> (t & 63) & 1;
			swap ^= bit;
			Field448.ConditionalSwap(0 - swap, ref x2, ref x3);
			Field448.ConditionalSwap(0 - swap, ref z2, ref z3);
			swap = bit;
			LadderStep(in x1, ref x2, ref z2, ref x3, ref z3);
		}

		Field448.ConditionalSwap(0 - swap, ref x2, ref x3);
		Field448.ConditionalSwap(0 - swap, ref z2, ref z3);
		x = x2;
		z = z2;
		limbs.ZeroMemory();
		x2.ZeroMemory();
		z2.ZeroMemory();
		x3.ZeroMemory();
		z3.ZeroMemory();
	}

	// [s]B = Untwist([s]Base) by the combs of TwistedBaseTable on the twisted curve. The top tooth of a comb gives its sign: a top digit of −1 negates the entry of the lower teeth complemented. Every comb value is nonzero, so the first one starts the point. The last product before a doubling or Untwist gives projective coordinates, which is all that those take.
	[SkipLocalsInit]
	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		const int teeth = TwistedBaseTable.Teeth;
		const int spacing = TwistedBaseTable.Spacing;
		const int combs = TwistedBaseTable.CombCount;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<ulong> digits = stackalloc ulong[ScalarDigits.CombLimbCount];
		Span<byte> entryStorage = stackalloc byte[AlignedScratch.StorageLength<TwistedNielsPoint>(1)];
		ref TwistedNielsPoint entry = ref AlignedScratch.AlignEntry<TwistedNielsPoint>(entryStorage);
		ScalarDigits.ReadLimbs(scalar, limbs);
		ScalarDigits.SignedComb(limbs, TwistedBaseTable.DigitCount, digits);
		Unsafe.SkipInit(out EdwardsPoint point);
		Unsafe.SkipInit(out EdwardsCompletedPoint sum);
		ref EdwardsProjectivePoint projective = ref Unsafe.As<EdwardsPoint, EdwardsProjectivePoint>(ref point);

		for (int i = spacing - 1; i >= 0; --i)
		{
			if (i < spacing - 1)
			{
				TwistedEdwards448.Double(in projective, out sum);
				Edwards448.ToExtended(in sum, out point);
			}

			for (int j = 0; j < combs; ++j)
			{
				uint index = ScalarDigits.CombIndex(digits, i + spacing * teeth * j, spacing, teeth);
				ulong negative = (ulong)(index >> teeth - 1) - 1;
				TwistedBaseTable.Select(j, (index ^ (uint)negative) & TwistedBaseTable.CombLength - 1, negative, out entry);

				if (i == spacing - 1 && j is 0)
				{
					TwistedEdwards448.FromNiels(in entry, out point);
					continue;
				}

				TwistedEdwards448.AddNiels(in point, in entry, out sum);

				if (j < combs - 1)
				{
					Edwards448.ToExtended(in sum, out point);
				}
				else
				{
					Edwards448.ToProjective(in sum, out projective);
				}
			}
		}

		TwistedEdwards448.Untwist(in projective, out sum);
		Edwards448.ToExtended(in sum, out result);
		limbs.ZeroMemory();
		digits.ZeroMemory();
		entryStorage.ZeroMemory();
		point.ZeroMemory();
		sum.ZeroMemory();
	}

	// Interleaves the NAFs of a and b. A doubling that no addition follows goes to projective coordinates, which need one product fewer than extended ones.
	[SkipLocalsInit]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int digitCount = 8 * Edwards448.ScalarLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[digitCount];
		Span<sbyte> baseDigits = stackalloc sbyte[digitCount];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = NonAdjacentForm.Recode(limbs, 0, digitCount - 1, PointWidth, pointDigits);
		ScalarDigits.ReadLimbs(b, limbs);
		top = Math.Max(top, NonAdjacentForm.Recode(limbs, 0, digitCount - 1, EdwardsVariableTimeBaseTable.Width, baseDigits));
		Edwards448.Identity(out result);

		if (top < 0)
		{
			return;
		}

		Span<EdwardsCachedPoint> pointMultiples = stackalloc EdwardsCachedPoint[1 << PointWidth - 2];
		BuildOddMultiples(in point, pointMultiples);
		ReadOnlySpan<EdwardsAffinePoint> baseMultiples = EdwardsVariableTimeBaseTable.Entries;
		EdwardsProjectivePoint sum = Edwards448.AsProjective(in result);

		for (int i = top; ; --i)
		{
			Edwards448.Double(in sum, out EdwardsCompletedPoint t);
			int digit = pointDigits[i];

			if (digit is not 0)
			{
				Edwards448.ToExtended(in t, out result);

				if (digit > 0)
				{
					Edwards448.Add(in result, in pointMultiples[digit >> 1], out t);
				}
				else
				{
					Edwards448.Subtract(in result, in pointMultiples[-digit >> 1], out t);
				}
			}

			digit = baseDigits[i];

			if (digit is not 0)
			{
				Edwards448.ToExtended(in t, out result);

				if (digit > 0)
				{
					Edwards448.AddAffine(in result, in baseMultiples[digit >> 1], out t);
				}
				else
				{
					Edwards448.SubtractAffine(in result, in baseMultiples[-digit >> 1], out t);
				}
			}

			if (i is 0)
			{
				Edwards448.ToExtended(in t, out result);
				return;
			}

			Edwards448.ToProjective(in t, out sum);
		}
	}

	// Each part of a and of b has a NAF of its own, which needs only the doublings of one part.
	[SkipLocalsInit]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int parts = EdwardsVariableTimePointTable.PartCount;
		const int partLength = EdwardsVariableTimePointTable.PartLength;
		const int partEntries = EdwardsVariableTimePointTable.PartEntryCount;
		const int baseEntries = EdwardsVariableTimeBaseTable.PartEntryCount;
		const int stride = partLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[parts * stride];
		Span<sbyte> baseDigits = stackalloc sbyte[parts * stride];
		int top = -1;
		ScalarDigits.ReadLimbs(a, limbs);

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, NonAdjacentForm.Recode(limbs, c * partLength, partLength, EdwardsVariableTimePointTable.Width, pointDigits.Slice(c * stride, stride)));
		}

		ScalarDigits.ReadLimbs(b, limbs);

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, NonAdjacentForm.Recode(limbs, c * partLength, partLength, EdwardsVariableTimeBaseTable.PartWidth, baseDigits.Slice(c * stride, stride)));
		}

		ReadOnlySpan<EdwardsAffinePoint> baseTable = EdwardsVariableTimeBaseTable.Parts;
		Edwards448.Identity(out result);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				Edwards448.Double(in result, out result);
			}

			for (int c = 0; c < parts; ++c)
			{
				AddDigit(ref result, pointDigits[c * stride + i], pointTable.Slice(c * partEntries, partEntries));
				AddDigit(ref result, baseDigits[c * stride + i], baseTable.Slice(c * baseEntries, baseEntries));
			}
		}
	}

	// One step of RFC 7748 §5: (x2 : z2) doubles and (x3 : z3) becomes the sum of the two, whose difference has u-coordinate x1. The sums that go into the products are at 2 and the differences at 3, in the bounds of Edwards448, so each square is within 3.5 and each product within 6; MultiplySmall takes E at 3.
	private static void LadderStep(in Field448 x1, ref Field448 x2, ref Field448 z2, ref Field448 x3, ref Field448 z3)
	{
		Field448.Add(in x2, in z2, out Field448 a);
		Field448.Subtract(in x2, in z2, out Field448 b);
		Field448.Add(in x3, in z3, out Field448 c);
		Field448.Subtract(in x3, in z3, out Field448 d);
		Field448.Square(in a, out Field448 aa);
		Field448.Square(in b, out Field448 bb);
		Field448.Multiply(in d, in a, out Field448 da);
		Field448.Multiply(in c, in b, out Field448 cb);
		Field448.Subtract(in aa, in bb, out Field448 e);
		Field448.Add(in da, in cb, out Field448 sum);
		Field448.Subtract(in da, in cb, out Field448 difference);
		Field448.Square(in sum, out x3);
		Field448.Square(in difference, out difference);
		Field448.Multiply(in x1, in difference, out z3);
		Field448.Multiply(in aa, in bb, out x2);
		Field448.MultiplySmall(in e, A24, out Field448 t);
		Field448.Add(in aa, in t, out t);
		Field448.Multiply(in e, in t, out z2);
	}

	// Adds digit·P to result for the odd multiples P, 3P, … in multiples, for a public digit.
	private static void AddDigit(ref EdwardsPoint result, int digit, ReadOnlySpan<EdwardsAffinePoint> multiples)
	{
		if (digit is 0)
		{
			return;
		}

		EdwardsCompletedPoint sum;

		if (digit > 0)
		{
			Edwards448.AddAffine(in result, in multiples[digit >> 1], out sum);
		}
		else
		{
			Edwards448.SubtractAffine(in result, in multiples[-digit >> 1], out sum);
		}

		Edwards448.ToExtended(in sum, out result);
	}

	// Sets multiples[j] to (2j + 1)·A: A, then (j + 2)·A = j·A + 2A.
	private static void BuildOddMultiples(in EdwardsPoint point, Span<EdwardsCachedPoint> multiples)
	{
		Edwards448.Double(in point, out EdwardsPoint twice);
		Edwards448.ToCached(in twice, out EdwardsCachedPoint twiceCached);
		EdwardsPoint multiple = point;
		Edwards448.ToCached(in multiple, out multiples[0]);

		for (int j = 1; j < multiples.Length; ++j)
		{
			Edwards448.Add(in multiple, in twiceCached, out EdwardsCompletedPoint sum);
			Edwards448.ToExtended(in sum, out multiple);
			Edwards448.ToCached(in multiple, out multiples[j]);
		}
	}
}
