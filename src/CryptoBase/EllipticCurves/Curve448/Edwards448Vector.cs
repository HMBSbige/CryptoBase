namespace CryptoBase.EllipticCurves.Curve448;

// The fixed-base and double-base products of ICurve448Kernel, four field elements at a time, by the formulas of IEdwardsField448x4.
internal static class Edwards448Vector<TField> where TField : unmanaged, IEdwardsField448x4<TField>
{
	// The NAF width of the point in DoubleScalarMultiplyVariableTime.
	private const int PointWidth = 5;

	private const int PointMultipleCount = 1 << PointWidth - 2;

	// As Curve448Scalar.MultiplyBase, with each comb value after the first selected into the scratch by TField.SelectBase. The point stays in lanes until Untwist, which TwistedEdwards448 takes.
	[SkipLocalsInit]
	internal static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		const int spacing = TwistedBaseTable.Spacing;
		const int combs = TwistedBaseTable.CombCount;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<ulong> digits = stackalloc ulong[ScalarDigits.CombLimbCount];
		int count = 1 + TField.ScratchLength;
		Span<byte> storage = stackalloc byte[Curve448Vector<TField>.StorageLength(count)];
		Span<TField> values = Curve448Vector<TField>.Align(storage, count);
		ref TField point = ref values[0];
		ref TField scratch = ref values[1];
		ScalarDigits.ReadLimbs(scalar, limbs);
		ScalarDigits.SignedComb(limbs, TwistedBaseTable.DigitCount, digits);
		Start(digits, out result, ref point);

		for (int i = spacing - 1; i >= 0; --i)
		{
			if (i < spacing - 1)
			{
				TField.TwistedDouble(ref point, ref scratch);
			}

			for (int j = i == spacing - 1 ? 1 : 0; j < combs; ++j)
			{
				AddComb(digits, i, j, ref point, ref scratch);
			}
		}

		TField.Extract(in point, out result.X, out result.Y, out result.Z, out result.T);
		TwistedEdwards448.Untwist(in Edwards448.AsProjective(in result), out EdwardsCompletedPoint sum);
		Edwards448.ToExtended(in sum, out result);
		limbs.ZeroMemory();
		digits.ZeroMemory();
		storage.ZeroMemory();
		sum.ZeroMemory();
	}

	// The value of comb 0 at the top offset, (4x : 4y : 4 : 4xy) by FromNiels, in point and in lanes.
	// ReSharper disable once RedundantAssignment
	private static void Start(ReadOnlySpan<ulong> digits, out EdwardsPoint point, ref TField lanes)
	{
		const int teeth = TwistedBaseTable.Teeth;
		const int spacing = TwistedBaseTable.Spacing;
		uint index = ScalarDigits.CombIndex(digits, spacing - 1, spacing, teeth);
		ulong negative = (ulong)(index >> teeth - 1) - 1;
		TwistedBaseTable.Select(0, (index ^ (uint)negative) & TwistedBaseTable.CombLength - 1, negative, out TwistedNielsPoint entry);
		TwistedEdwards448.FromNiels(in entry, out point);
		TField.Create(in point.X, in point.Y, in point.Z, in point.T, out lanes);
		entry.ZeroMemory();
	}

	// Adds the value of comb at offset i, whose top digit gives its sign: a top digit of −1 negates the entry of the lower teeth complemented.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddComb(ReadOnlySpan<ulong> digits, int i, int comb, ref TField point, ref TField scratch)
	{
		const int teeth = TwistedBaseTable.Teeth;
		const int spacing = TwistedBaseTable.Spacing;
		uint index = ScalarDigits.CombIndex(digits, i + spacing * teeth * comb, spacing, teeth);
		ulong negative = (ulong)(index >> teeth - 1) - 1;
		TField.SelectBase(comb, (index ^ (uint)negative) & TwistedBaseTable.CombLength - 1, negative, ref scratch);
		TField.TwistedAdd(ref point, ref scratch);
	}

	// Interleaves the NAFs of a and b, as Curve448Scalar.DoubleScalarMultiplyVariableTime does, with the odd multiples of A brought to affine coordinates by one inversion, so that every addition takes the affine right operand of TField.Add.
	[SkipLocalsInit]
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int digitCount = 8 * Edwards448.ScalarLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[digitCount];
		Span<sbyte> baseDigits = stackalloc sbyte[digitCount];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = ScalarDigits.NonAdjacentForm(limbs, 0, digitCount - 1, PointWidth, pointDigits);
		ScalarDigits.ReadLimbs(b, limbs);
		top = Math.Max(top, ScalarDigits.NonAdjacentForm(limbs, 0, digitCount - 1, EdwardsVariableTimeBaseTable.Width, baseDigits));

		if (top < 0)
		{
			Edwards448.Identity(out result);
			return;
		}

		Span<EdwardsAffinePoint> pointMultiples = stackalloc EdwardsAffinePoint[PointMultipleCount];
		BuildOddMultiples(in point, pointMultiples);
		ReadOnlySpan<EdwardsAffinePoint> baseMultiples = EdwardsVariableTimeBaseTable.Entries;
		int count = 1 + TField.ScratchLength;
		Span<TField> values = Curve448Vector<TField>.Align(stackalloc byte[Curve448Vector<TField>.StorageLength(count)], count);
		ref TField sum = ref values[0];
		ref TField scratch = ref values[1];
		Identity(out sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				TField.Double(ref sum, ref scratch);
			}

			AddDigit(ref sum, pointDigits[i], pointMultiples, ref scratch);
			AddDigit(ref sum, baseDigits[i], baseMultiples, ref scratch);
		}

		TField.Extract(in sum, out result.X, out result.Y, out result.Z, out result.T);
	}

	// As Curve448Scalar.DoubleScalarMultiplyVariableTime with the table of EdwardsVariableTimePointTable.
	[SkipLocalsInit]
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
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
			top = Math.Max(top, ScalarDigits.NonAdjacentForm(limbs, c * partLength, partLength, EdwardsVariableTimePointTable.Width, pointDigits.Slice(c * stride, stride)));
		}

		ScalarDigits.ReadLimbs(b, limbs);

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, ScalarDigits.NonAdjacentForm(limbs, c * partLength, partLength, EdwardsVariableTimeBaseTable.PartWidth, baseDigits.Slice(c * stride, stride)));
		}

		ReadOnlySpan<EdwardsAffinePoint> baseTable = EdwardsVariableTimeBaseTable.Parts;
		int count = 1 + TField.ScratchLength;
		Span<TField> values = Curve448Vector<TField>.Align(stackalloc byte[Curve448Vector<TField>.StorageLength(count)], count);
		ref TField sum = ref values[0];
		ref TField scratch = ref values[1];
		Identity(out sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				TField.Double(ref sum, ref scratch);
			}

			for (int c = 0; c < parts; ++c)
			{
				AddDigit(ref sum, pointDigits[c * stride + i], pointTable.Slice(c * partEntries, partEntries), ref scratch);
				AddDigit(ref sum, baseDigits[c * stride + i], baseTable.Slice(c * baseEntries, baseEntries), ref scratch);
			}
		}

		TField.Extract(in sum, out result.X, out result.Y, out result.Z, out result.T);
	}

	// (0, 1, 1, 0).
	private static void Identity(out TField result)
	{
		Field448 zero = default;
		TField.Create(in zero, in Field448.One, in Field448.One, in zero, out result);
	}

	// Adds digit·P to sum for the odd multiples P, 3P, … in multiples, for a public digit.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AddDigit(ref TField sum, int digit, ReadOnlySpan<EdwardsAffinePoint> multiples, ref TField scratch)
	{
		if (digit is 0)
		{
			return;
		}

		TField.LoadAffine(in multiples[Math.Abs(digit) >> 1], digit < 0, ref scratch);
		TField.Add(ref sum, ref scratch);
	}

	// Sets multiples[j] to the affine (2j + 1)·A: A, then (j + 2)·A = j·A + 2A, by the formulas of Edwards448.
	private static void BuildOddMultiples(in EdwardsPoint point, Span<EdwardsAffinePoint> multiples)
	{
		Span<EdwardsPoint> points = stackalloc EdwardsPoint[PointMultipleCount];
		points[0] = point;
		Edwards448.Double(in point, out EdwardsPoint twice);
		Edwards448.ToCached(in twice, out EdwardsCachedPoint cached);

		for (int j = 1; j < points.Length; ++j)
		{
			Edwards448.Add(in points[j - 1], in cached, out EdwardsCompletedPoint sum);
			Edwards448.ToExtended(in sum, out points[j]);
		}

		Edwards448.ToAffineVariableTime(points, multiples);
	}
}
