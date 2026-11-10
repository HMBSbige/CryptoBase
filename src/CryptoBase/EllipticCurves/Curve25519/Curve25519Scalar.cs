namespace CryptoBase.EllipticCurves.Curve25519;

// The kernel of Field25519 alone, for every platform.
internal readonly struct Curve25519Scalar : ICurve25519Kernel
{
	// (A − 2)/4 for the Montgomery coefficient A = 486662.
	private const uint A24 = 121665;

	// The NAF width of the point in DoubleScalarMultiplyVariableTime.
	private const int PointWidth = 5;

	public static bool IsSupported => true;

	// Each step takes the bit of k from 254 down to 0. The swap mask is the XOR of the bit with the one before, so only arithmetic on k decides which pair each step doubles.
	[SkipLocalsInit]
	public static void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		ScalarDigits.ReadLimbs(scalar, limbs);
		Field25519 x1 = u;
		Field25519 x2 = Field25519.One;
		Field25519 z2 = default;
		Field25519 x3 = u;
		Field25519 z3 = Field25519.One;
		ulong swap = 0;

		for (int t = 254; t >= 0; --t)
		{
			ulong bit = limbs[t >> 6] >> (t & 63) & 1;
			swap ^= bit;
			Field25519.ConditionalSwap(0 - swap, ref x2, ref x3);
			Field25519.ConditionalSwap(0 - swap, ref z2, ref z3);
			swap = bit;
			LadderStep(in x1, ref x2, ref z2, ref x3, ref z3);
		}

		Field25519.ConditionalSwap(0 - swap, ref x2, ref x3);
		Field25519.ConditionalSwap(0 - swap, ref z2, ref z3);
		x = x2;
		z = z2;
		limbs.ZeroMemory();
		x2.ZeroMemory();
		z2.ZeroMemory();
		x3.ZeroMemory();
		z3.ZeroMemory();
	}

	// The windows of EdwardsBaseTable need no doublings: window i adds d_i·2^(wi)·B, and the complete addition takes the identity that a digit of 0 selects.
	[SkipLocalsInit]
	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> digits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		Span<byte> entryStorage = stackalloc byte[AlignedScratch.StorageLength<EdwardsNielsPoint>(1)];
		ref EdwardsNielsPoint entry = ref AlignedScratch.AlignEntry<EdwardsNielsPoint>(entryStorage);
		ScalarDigits.ReadLimbs(scalar, limbs);
		LimbArithmetic.RecodeSignedWindows(limbs, EdwardsBaseTable.Width, digits);
		EdwardsBaseTable.Select(0, digits[0], out entry);
		FromNiels(in entry, out result);
		Unsafe.SkipInit(out EdwardsCompletedPoint sum);

		for (int i = 1; i < digits.Length; ++i)
		{
			EdwardsBaseTable.Select(i, digits[i], out entry);
			Edwards25519.AddNiels(in result, in entry, out sum);
			Edwards25519.ToExtended(in sum, out result);
		}

		limbs.ZeroMemory();
		digits.ZeroMemory();
		entryStorage.ZeroMemory();
		sum.ZeroMemory();
	}

	// Interleaves the NAFs of a and b. A doubling that no addition follows goes to projective coordinates, which need one product fewer than extended ones.
	[SkipLocalsInit]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int digitCount = 8 * Edwards25519.ScalarLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[digitCount];
		Span<sbyte> baseDigits = stackalloc sbyte[digitCount];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = NonAdjacentForm.Recode(limbs, 0, digitCount - 1, PointWidth, pointDigits);
		ScalarDigits.ReadLimbs(b, limbs);
		top = Math.Max(top, NonAdjacentForm.Recode(limbs, 0, digitCount - 1, EdwardsVariableTimeBaseTable.Width, baseDigits));
		Edwards25519.Identity(out result);

		if (top < 0)
		{
			return;
		}

		Span<EdwardsCachedPoint> pointMultiples = stackalloc EdwardsCachedPoint[1 << PointWidth - 2];
		BuildOddMultiples(in point, pointMultiples);
		ReadOnlySpan<EdwardsNielsPoint> baseMultiples = EdwardsVariableTimeBaseTable.Entries;
		EdwardsProjectivePoint sum = Edwards25519.AsProjective(in result);

		for (int i = top; ; --i)
		{
			Edwards25519.Double(in sum, out EdwardsCompletedPoint t);
			int digit = pointDigits[i];

			if (digit is not 0)
			{
				Edwards25519.ToExtended(in t, out result);

				if (digit > 0)
				{
					Edwards25519.Add(in result, in pointMultiples[digit >> 1], out t);
				}
				else
				{
					Edwards25519.Subtract(in result, in pointMultiples[-digit >> 1], out t);
				}
			}

			digit = baseDigits[i];

			if (digit is not 0)
			{
				Edwards25519.ToExtended(in t, out result);

				if (digit > 0)
				{
					Edwards25519.AddNiels(in result, in baseMultiples[digit >> 1], out t);
				}
				else
				{
					Edwards25519.SubtractNiels(in result, in baseMultiples[-digit >> 1], out t);
				}
			}

			if (i is 0)
			{
				Edwards25519.ToExtended(in t, out result);
				return;
			}

			Edwards25519.ToProjective(in t, out sum);
		}
	}

	// Each part of a has a NAF of its own, which needs only the doublings of one part, and [b]B follows from the windows of EdwardsBaseTable, which need none.
	[SkipLocalsInit]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int parts = EdwardsVariableTimePointTable.PartCount;
		const int partLength = EdwardsVariableTimePointTable.PartLength;
		const int partEntries = EdwardsVariableTimePointTable.PartEntryCount;
		const int stride = partLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[parts * stride];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = -1;

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, NonAdjacentForm.Recode(limbs, c * partLength, partLength, EdwardsVariableTimePointTable.Width, pointDigits.Slice(c * stride, stride)));
		}

		Edwards25519.Identity(out result);
		Unsafe.SkipInit(out EdwardsCompletedPoint sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				Edwards25519.Double(in result, out result);
			}

			for (int c = 0; c < parts; ++c)
			{
				int digit = pointDigits[c * stride + i];

				if (digit is not 0)
				{
					ref readonly EdwardsNielsPoint entry = ref pointTable[c * partEntries + (Math.Abs(digit) >> 1)];

					if (digit > 0)
					{
						Edwards25519.AddNiels(in result, in entry, out sum);
					}
					else
					{
						Edwards25519.SubtractNiels(in result, in entry, out sum);
					}

					Edwards25519.ToExtended(in sum, out result);
				}
			}
		}

		ScalarDigits.ReadLimbs(b, limbs);
		int width = EdwardsBaseTable.Width;
		int windowLength = EdwardsBaseTable.WindowLength;
		Span<sbyte> baseDigits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		LimbArithmetic.RecodeSignedWindows(limbs, width, baseDigits);

		for (int i = 0; i < baseDigits.Length; ++i)
		{
			int digit = baseDigits[i];

			if (digit is not 0)
			{
				EdwardsBaseTable.Read(i * windowLength + Math.Abs(digit) - 1, out EdwardsNielsPoint entry);

				if (digit > 0)
				{
					Edwards25519.AddNiels(in result, in entry, out sum);
				}
				else
				{
					Edwards25519.SubtractNiels(in result, in entry, out sum);
				}

				Edwards25519.ToExtended(in sum, out result);
			}
		}
	}

	// One step of RFC 7748 §5: (x2 : z2) doubles and (x3 : z3) becomes the sum of the two, whose difference has u-coordinate x1. The sums and differences that go into the products are below 2^52.6 and the products tight.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void LadderStep(in Field25519 x1, ref Field25519 x2, ref Field25519 z2, ref Field25519 x3, ref Field25519 z3)
	{
		Field25519.Add(in x2, in z2, out Field25519 a);
		Field25519.Subtract(in x2, in z2, out Field25519 b);
		Field25519.Add(in x3, in z3, out Field25519 c);
		Field25519.Subtract(in x3, in z3, out Field25519 d);
		Field25519.SquareCore(in a, out Field25519 aa);
		Field25519.SquareCore(in b, out Field25519 bb);
		Field25519.MultiplyCore(in d, in a, out Field25519 da);
		Field25519.MultiplyCore(in c, in b, out Field25519 cb);
		Field25519.Subtract(in aa, in bb, out Field25519 e);
		Field25519.Add(in da, in cb, out Field25519 sum);
		Field25519.Subtract(in da, in cb, out Field25519 difference);
		Field25519.SquareCore(in sum, out x3);
		Field25519.SquareCore(in difference, out difference);
		Field25519.MultiplyCore(in x1, in difference, out z3);
		Field25519.MultiplyCore(in aa, in bb, out x2);
		Field25519.MultiplySmall(in e, A24, out Field25519 t);
		Field25519.Add(in aa, in t, out t);
		Field25519.MultiplyCore(in e, in t, out z2);
	}

	// (4x : 4y : 4 : 4xy) from (y + x, y − x, 2dxy): twice the difference and the sum of the first two are 4x and 4y, and their product is 4xy.
	internal static void FromNiels(in EdwardsNielsPoint point, out EdwardsPoint result)
	{
		Field25519.Subtract(in point.YPlusX, in point.YMinusX, out Field25519 twoX);
		Field25519.Add(in point.YPlusX, in point.YMinusX, out Field25519 twoY);
		Field25519.Multiply(in twoX, in twoY, out result.T);
		Field25519.Add(in twoX, in twoX, out twoX);
		Field25519.Add(in twoY, in twoY, out twoY);
		Field25519.Carry(in twoX, out result.X);
		Field25519.Carry(in twoY, out result.Y);
		result.Z = default;
		result.Z.L0 = 4;
		twoX.ZeroMemory();
		twoY.ZeroMemory();
	}

	// Sets multiples[j] to (2j + 1)·A: A, then (j + 2)·A = j·A + 2A.
	private static void BuildOddMultiples(in EdwardsPoint point, Span<EdwardsCachedPoint> multiples)
	{
		Edwards25519.Double(in point, out EdwardsPoint twice);
		Edwards25519.ToCached(in twice, out EdwardsCachedPoint twiceCached);
		EdwardsPoint multiple = point;
		Edwards25519.ToCached(in multiple, out multiples[0]);

		for (int j = 1; j < multiples.Length; ++j)
		{
			Edwards25519.Add(in multiple, in twiceCached, out EdwardsCompletedPoint sum);
			Edwards25519.ToExtended(in sum, out multiple);
			Edwards25519.ToCached(in multiple, out multiples[j]);
		}
	}
}
