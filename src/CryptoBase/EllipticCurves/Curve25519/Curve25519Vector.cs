namespace CryptoBase.EllipticCurves.Curve25519;

// The scalar multiplications of ICurve25519Kernel, four field elements at a time, by the formulas of EdwardsLanes and a vectorized ladder.
internal static class Curve25519Vector<TField> where TField : unmanaged, IField25519x4<TField>
{
	// d = −121665/121666, so 121666·(Y − X, Y + X, 2Z, 2dT) = (121666·(Y − X), 121666·(Y + X), 243332·Z, −243330·T) takes small constants alone.
	private const uint ScaledOne = 121666;
	private const uint ScaledTwo = 2 * 121666;
	private const uint ScaledTwoD = 2 * 121665;

	// The NAF width of the point in DoubleScalarMultiplyVariableTime.
	private const int PointWidth = 5;

	private const int PointMultipleCount = 1 << PointWidth - 2;

	private static ReadOnlySpan<ulong> TwoLimbs => [2, 0, 0, 0, 0];

	// Each step takes the bit of k from 254 down to 0, as Curve25519Scalar.Ladder does: the state (x2, z2, x3, z3) is swapped to (x3, z3, x2, z2) where the bit differs from the one before. A step is three products of four lanes: (A², B², DA, CB), then (AA·BB, E·(AA + a24·E), (DA + CB)², (DA − CB)²), whose lane D the third, by (1, 1, 1, u), turns into z3.
	[SkipLocalsInit]
	internal static void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		int count = 3 + TField.MultiplierLength;
		Span<TField> values = EdwardsLanes.Align<TField>(stackalloc byte[EdwardsLanes.StorageLength<TField>(count)], count);
		ref TField state = ref values[0];
		ref TField left = ref values[1];
		ref TField right = ref values[2];
		ref TField multiplier = ref values[3];
		ScalarDigits.ReadLimbs(scalar, limbs);
		Field25519 zero = default;
		TField.Create(in Field25519.One, in zero, in u, in Field25519.One, out state);
		TField.CreateMultiplier(in u, values.Slice(3));
		ulong swap = 0;

		for (int t = 254; t >= 0; --t)
		{
			ulong bit = limbs[t >> 6] >> (t & 63) & 1;
			swap ^= bit;
			TField.LadderOperands(in state, 0 - swap, out left, out right);
			swap = bit;
			TField.LadderProducts(in left, in right, in multiplier, out state);
		}

		TField.ConditionalSwapHalves(0 - swap, ref state);
		TField.Extract(in state, out x, out z, out Field25519 x3, out Field25519 z3);
		limbs.ZeroMemory();
		values.ZeroMemory();
		x3.ZeroMemory();
		z3.ZeroMemory();
	}

	// The windows of EdwardsBaseTable, as Curve25519Scalar.MultiplyBase takes them: the first entry starts the point, and each later one goes from its constant-time lookup into lanes by TField.SelectBase, without coordinates in memory between them.
	[SkipLocalsInit]
	internal static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> digits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		Span<TField> values = EdwardsLanes.Align<TField>(stackalloc byte[EdwardsLanes.StorageLength<TField>(4)], 4);
		ref TField point = ref values[0];
		ref TField cached = ref values[1];
		ref TField left = ref values[2];
		ref TField right = ref values[3];
		Span<byte> entryStorage = stackalloc byte[EdwardsLanes.EntryStorageLength];
		ref EdwardsNielsPoint entry = ref EdwardsLanes.AlignEntry(entryStorage);
		ScalarDigits.ReadLimbs(scalar, limbs);
		ScalarDigits.SignedWindows(limbs, EdwardsBaseTable.Width, digits);
		EdwardsBaseTable.Select(0, digits[0], out entry);
		Curve25519Scalar.FromNiels(in entry, out result);
		TField.Create(in result.X, in result.Y, in result.Z, in result.T, out point);

		for (int i = 1; i < digits.Length; ++i)
		{
			TField.SelectBase(i, digits[i], out cached);
			EdwardsLanes.Add(ref point, in cached, ref left, ref right);
		}

		TField.Extract(in point, out result.X, out result.Y, out result.Z, out result.T);
		limbs.ZeroMemory();
		digits.ZeroMemory();
		entryStorage.ZeroMemory();
		values.ZeroMemory();
	}

	// Interleaves the NAFs of a and b, as Curve25519Scalar.DoubleScalarMultiplyVariableTime does.
	[SkipLocalsInit]
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int digitCount = 8 * Edwards25519.ScalarLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[digitCount];
		Span<sbyte> baseDigits = stackalloc sbyte[digitCount];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = NonAdjacentForm.Recode(limbs, 0, digitCount - 1, PointWidth, pointDigits);
		ScalarDigits.ReadLimbs(b, limbs);
		top = Math.Max(top, NonAdjacentForm.Recode(limbs, 0, digitCount - 1, EdwardsVariableTimeBaseTable.Width, baseDigits));

		if (top < 0)
		{
			Edwards25519.Identity(out result);
			return;
		}

		Span<TField> values = EdwardsLanes.Align<TField>(stackalloc byte[EdwardsLanes.StorageLength<TField>(PointMultipleCount + 4)], PointMultipleCount + 4);
		Span<TField> pointMultiples = values.Slice(0, PointMultipleCount);
		ref TField sum = ref values[PointMultipleCount];
		ref TField cached = ref values[PointMultipleCount + 1];
		ref TField left = ref values[PointMultipleCount + 2];
		ref TField right = ref values[PointMultipleCount + 3];
		BuildOddMultiples(in point, pointMultiples, out sum, ref cached, ref left, ref right);
		ReadOnlySpan<EdwardsNielsPoint> baseMultiples = EdwardsVariableTimeBaseTable.Entries;
		Identity(out sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				EdwardsLanes.Double(ref sum, ref left, ref right);
			}

			int digit = pointDigits[i];

			if (digit > 0)
			{
				EdwardsLanes.Add(ref sum, in pointMultiples[digit >> 1], ref left, ref right);
			}
			else if (digit < 0)
			{
				TField.NegateCached(in pointMultiples[-digit >> 1], out cached);
				EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
			}

			digit = baseDigits[i];

			if (digit is not 0)
			{
				CacheVariableTime(in baseMultiples[Math.Abs(digit) >> 1], digit < 0, out cached);
				EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
			}
		}

		TField.Extract(in sum, out result.X, out result.Y, out result.Z, out result.T);
	}

	// As Edwards25519.DoubleScalarMultiplyVariableTime with the table of EdwardsVariableTimePointTable.
	[SkipLocalsInit]
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int parts = EdwardsVariableTimePointTable.PartCount;
		const int partLength = EdwardsVariableTimePointTable.PartLength;
		const int partEntries = EdwardsVariableTimePointTable.PartEntryCount;
		const int stride = partLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[parts * stride];
		Span<sbyte> baseDigits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		Span<TField> values = EdwardsLanes.Align<TField>(stackalloc byte[EdwardsLanes.StorageLength<TField>(4)], 4);
		ref TField sum = ref values[0];
		ref TField cached = ref values[1];
		ref TField left = ref values[2];
		ref TField right = ref values[3];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = -1;

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, NonAdjacentForm.Recode(limbs, c * partLength, partLength, EdwardsVariableTimePointTable.Width, pointDigits.Slice(c * stride, stride)));
		}

		Identity(out sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				EdwardsLanes.Double(ref sum, ref left, ref right);
			}

			for (int c = 0; c < parts; ++c)
			{
				int digit = pointDigits[c * stride + i];

				if (digit is not 0)
				{
					CacheVariableTime(in pointTable[c * partEntries + (Math.Abs(digit) >> 1)], digit < 0, out cached);
					EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
				}
			}
		}

		ScalarDigits.ReadLimbs(b, limbs);
		ScalarDigits.SignedWindows(limbs, EdwardsBaseTable.Width, baseDigits);
		int windowLength = EdwardsBaseTable.WindowLength;

		for (int i = 0; i < baseDigits.Length; ++i)
		{
			int digit = baseDigits[i];

			if (digit is not 0)
			{
				EdwardsBaseTable.Read(i * windowLength + Math.Abs(digit) - 1, out EdwardsNielsPoint entry);
				CacheVariableTime(in entry, digit < 0, out cached);
				EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
			}
		}

		TField.Extract(in sum, out result.X, out result.Y, out result.Z, out result.T);
	}

	// (0, 1, 1, 0).
	private static void Identity(out TField result)
	{
		Field25519 zero = default;
		TField.Create(in zero, in Field25519.One, in Field25519.One, in zero, out result);
	}

	// 121666·(Y − X, Y + X, 2Z, 2dT).
	private static void Cache(in TField point, out TField result)
	{
		TField.DiffSum(in point, out result);
		TField.MultiplySmall(in result, ScaledOne, ScaledOne, ScaledTwo, ScaledTwoD, out result);
		TField.NegateD(in result, out result);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Cache(in EdwardsNielsPoint point, out TField result)
	{
		TField.Create(in point.YMinusX, in point.YPlusX, in Field25519.FromConstant(TwoLimbs), in point.TwoDXY, out result);
	}

	// The point or, for a public negative digit, its negation (y − x, y + x, −2dxy).
	private static void CacheVariableTime(in EdwardsNielsPoint point, bool negative, out TField result)
	{
		if (!negative)
		{
			Cache(in point, out result);
			return;
		}

		Field25519.Negate(in point.TwoDXY, out Field25519 twoDXY);
		TField.Create(in point.YPlusX, in point.YMinusX, in Field25519.FromConstant(TwoLimbs), in twoDXY, out result);
	}

	// Sets multiples[j] to the cached (2j + 1)·A: A, then (j + 2)·A = 2A + j·A.
	private static void BuildOddMultiples(in EdwardsPoint point, Span<TField> multiples, out TField twice, ref TField sum, ref TField left, ref TField right)
	{
		TField.Create(in point.X, in point.Y, in point.Z, in point.T, out twice);
		Cache(in twice, out multiples[0]);
		EdwardsLanes.Double(ref twice, ref left, ref right);

		for (int j = 1; j < multiples.Length; ++j)
		{
			sum = twice;
			EdwardsLanes.Add(ref sum, in multiples[j - 1], ref left, ref right);
			Cache(in sum, out multiples[j]);
		}
	}
}
