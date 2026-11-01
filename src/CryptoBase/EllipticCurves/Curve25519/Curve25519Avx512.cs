namespace CryptoBase.EllipticCurves.Curve25519;

// Two points at once in the groups of Field25519x8Avx512, for the products whose additions fall into two independent chains: the windows of MultiplyBase, even ones in group 0 and odd ones in group 1, and the cached-table product, whose parts and windows the groups share out. Each chain is a point of its own, and the two add up at the end. The ladder and the double-base product have a single chain of doublings, which a second group would not shorten, and take Curve25519Avx2.
internal readonly struct Curve25519Avx512 : ICurve25519Kernel
{
	private static ReadOnlySpan<ulong> TwoLimbs => [2, 0, 0, 0, 0];

	public static bool IsSupported => Field25519x8Avx512.IsSupported;

	public static void Ladder(ReadOnlySpan<byte> scalar, in Field25519 u, out Field25519 x, out Field25519 z)
	{
		Curve25519Avx2.Ladder(scalar, in u, out x, out z);
	}

	// Window 0 starts group 0 and window 1 group 1, and each later pair adds to both; the last window, alone, pairs with the identity.
	[SkipLocalsInit]
	public static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> digits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		Span<Field25519x8Avx512> values = EdwardsLanes.Align<Field25519x8Avx512>(stackalloc byte[EdwardsLanes.StorageLength<Field25519x8Avx512>(4)], 4);
		ref Field25519x8Avx512 point = ref values[0];
		ref Field25519x8Avx512 cached = ref values[1];
		ref Field25519x8Avx512 left = ref values[2];
		ref Field25519x8Avx512 right = ref values[3];
		Span<byte> firstStorage = stackalloc byte[EdwardsLanes.EntryStorageLength];
		Span<byte> secondStorage = stackalloc byte[EdwardsLanes.EntryStorageLength];
		ref EdwardsNielsPoint first = ref EdwardsLanes.AlignEntry(firstStorage);
		ref EdwardsNielsPoint second = ref EdwardsLanes.AlignEntry(secondStorage);
		ScalarDigits.ReadLimbs(scalar, limbs);
		ScalarDigits.SignedWindows(limbs, EdwardsBaseTable.Width, digits);
		EdwardsBaseTable.Select(0, digits[0], out first);
		EdwardsBaseTable.Select(1, digits[1], out second);
		Curve25519Scalar.FromNiels(in first, out result);
		Curve25519Scalar.FromNiels(in second, out EdwardsPoint other);
		Field25519x8Avx512.Create(in result.X, in result.Y, in result.Z, in result.T, in other.X, in other.Y, in other.Z, in other.T, out point);

		for (int i = 2; i < digits.Length; i += 2)
		{
			EdwardsBaseTable.Select(i, digits[i], out first);

			if (i + 1 < digits.Length)
			{
				EdwardsBaseTable.Select(i + 1, digits[i + 1], out second);
			}
			else
			{
				Identity(out second);
			}

			Cache(in first, in second, out cached);
			EdwardsLanes.Add(ref point, in cached, ref left, ref right);
		}

		Join(in point, out result);
		limbs.ZeroMemory();
		digits.ZeroMemory();
		firstStorage.ZeroMemory();
		secondStorage.ZeroMemory();
		other.ZeroMemory();
		values.ZeroMemory();
	}

	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Curve25519Avx2.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
	}

	// Group 0 takes the parts in the low half of the table and group 1 those in the high half, both doubled together; at each digit position the nonzero digits of the two halves pair up, the rest with the identity. The windows of [b]B pair up in the order they come.
	[SkipLocalsInit]
	public static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		const int parts = EdwardsVariableTimePointTable.PartCount;
		const int half = parts / 2;
		const int partLength = EdwardsVariableTimePointTable.PartLength;
		const int partEntries = EdwardsVariableTimePointTable.PartEntryCount;
		const int stride = partLength + 1;
		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		Span<sbyte> pointDigits = stackalloc sbyte[parts * stride];
		Span<sbyte> baseDigits = stackalloc sbyte[EdwardsBaseTable.WindowCount];
		Span<Field25519x8Avx512> values = EdwardsLanes.Align<Field25519x8Avx512>(stackalloc byte[EdwardsLanes.StorageLength<Field25519x8Avx512>(4)], 4);
		ref Field25519x8Avx512 sum = ref values[0];
		ref Field25519x8Avx512 cached = ref values[1];
		ref Field25519x8Avx512 left = ref values[2];
		ref Field25519x8Avx512 right = ref values[3];
		ScalarDigits.ReadLimbs(a, limbs);
		int top = -1;

		for (int c = 0; c < parts; ++c)
		{
			top = Math.Max(top, ScalarDigits.NonAdjacentForm(limbs, c * partLength, partLength, EdwardsVariableTimePointTable.Width, pointDigits.Slice(c * stride, stride)));
		}

		Identity(out EdwardsNielsPoint identity);
		Field25519 zero = default;
		Field25519x8Avx512.Create(in zero, in Field25519.One, in Field25519.One, in zero, in zero, in Field25519.One, in Field25519.One, in zero, out sum);

		for (int i = top; i >= 0; --i)
		{
			if (i < top)
			{
				EdwardsLanes.Double(ref sum, ref left, ref right);
			}

			int low = NextPart(pointDigits, i, 0, half);
			int high = NextPart(pointDigits, i, half, parts);

			while (low < half || high < parts)
			{
				int lowDigit = low < half ? pointDigits[low * stride + i] : 0;
				int highDigit = high < parts ? pointDigits[high * stride + i] : 0;
				ref readonly EdwardsNielsPoint lowEntry = ref lowDigit is 0 ? ref identity : ref pointTable[low * partEntries + (Math.Abs(lowDigit) >> 1)];
				ref readonly EdwardsNielsPoint highEntry = ref highDigit is 0 ? ref identity : ref pointTable[high * partEntries + (Math.Abs(highDigit) >> 1)];
				CacheVariableTime(in lowEntry, lowDigit < 0, in highEntry, highDigit < 0, out cached);
				EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
				low = NextPart(pointDigits, i, low + 1, half);
				high = NextPart(pointDigits, i, high + 1, parts);
			}
		}

		ScalarDigits.ReadLimbs(b, limbs);
		ScalarDigits.SignedWindows(limbs, EdwardsBaseTable.Width, baseDigits);
		int windowLength = EdwardsBaseTable.WindowLength;
		int pending = -1;

		for (int i = 0; i < baseDigits.Length; ++i)
		{
			if (baseDigits[i] is 0)
			{
				continue;
			}

			if (pending < 0)
			{
				pending = i;
				continue;
			}

			AddWindows(baseDigits, pending, i, windowLength, ref sum, out cached, ref left, ref right);
			pending = -1;
		}

		if (pending >= 0)
		{
			AddWindows(baseDigits, pending, -1, windowLength, ref sum, out cached, ref left, ref right);
		}

		Join(in sum, out result);
	}

	// The first part from start to end with a nonzero digit at position i, or end if there is none.
	private static int NextPart(ReadOnlySpan<sbyte> digits, int i, int start, int end)
	{
		const int stride = EdwardsVariableTimePointTable.PartLength + 1;
		int c = start;

		while (c < end && digits[c * stride + i] is 0)
		{
			++c;
		}

		return c;
	}

	// Adds window first to group 0 and window second, or the identity for −1, to group 1.
	private static void AddWindows(ReadOnlySpan<sbyte> digits, int first, int second, int windowLength, ref Field25519x8Avx512 sum, out Field25519x8Avx512 cached, ref Field25519x8Avx512 left, ref Field25519x8Avx512 right)
	{
		int firstDigit = digits[first];
		EdwardsBaseTable.Read(first * windowLength + Math.Abs(firstDigit) - 1, out EdwardsNielsPoint firstEntry);
		int secondDigit = 0;
		Identity(out EdwardsNielsPoint secondEntry);

		if (second >= 0)
		{
			secondDigit = digits[second];
			EdwardsBaseTable.Read(second * windowLength + Math.Abs(secondDigit) - 1, out secondEntry);
		}

		CacheVariableTime(in firstEntry, firstDigit < 0, in secondEntry, secondDigit < 0, out cached);
		EdwardsLanes.Add(ref sum, in cached, ref left, ref right);
	}

	// The Niels identity (1, 1, 0).
	private static void Identity(out EdwardsNielsPoint result)
	{
		result = default;
		result.YPlusX.L0 = 1;
		result.YMinusX.L0 = 1;
	}

	// (y − x, y + x, 2, 2dxy) of two Niels points, one per group.
	private static void Cache(in EdwardsNielsPoint first, in EdwardsNielsPoint second, out Field25519x8Avx512 result)
	{
		ref readonly Field25519 two = ref Field25519.FromConstant(TwoLimbs);
		Field25519x8Avx512.Create(in first.YMinusX, in first.YPlusX, in two, in first.TwoDXY, in second.YMinusX, in second.YPlusX, in two, in second.TwoDXY, out result);
	}

	// As Cache, each point negated, to (y + x, y − x, 2, −2dxy), for a public negative digit.
	private static void CacheVariableTime(in EdwardsNielsPoint first, bool firstNegative, in EdwardsNielsPoint second, bool secondNegative, out Field25519x8Avx512 result)
	{
		ref readonly Field25519 two = ref Field25519.FromConstant(TwoLimbs);
		Field25519 firstTwoDXY = first.TwoDXY;
		Field25519 secondTwoDXY = second.TwoDXY;

		if (firstNegative)
		{
			Field25519.Negate(in firstTwoDXY, out firstTwoDXY);
		}

		if (secondNegative)
		{
			Field25519.Negate(in secondTwoDXY, out secondTwoDXY);
		}

		ref readonly Field25519 firstMinus = ref firstNegative ? ref first.YPlusX : ref first.YMinusX;
		ref readonly Field25519 firstPlus = ref firstNegative ? ref first.YMinusX : ref first.YPlusX;
		ref readonly Field25519 secondMinus = ref secondNegative ? ref second.YPlusX : ref second.YMinusX;
		ref readonly Field25519 secondPlus = ref secondNegative ? ref second.YMinusX : ref second.YPlusX;
		Field25519x8Avx512.Create(in firstMinus, in firstPlus, in two, in firstTwoDXY, in secondMinus, in secondPlus, in two, in secondTwoDXY, out result);
	}

	// The sum of the points of the two groups, with every intermediate cleared, as the points may depend on a secret scalar.
	[SkipLocalsInit]
	private static void Join(in Field25519x8Avx512 value, out EdwardsPoint result)
	{
		Unsafe.SkipInit(out EdwardsPoint other);
		Field25519x8Avx512.Extract(in value, 0, out result.X, out result.Y, out result.Z, out result.T);
		Field25519x8Avx512.Extract(in value, 1, out other.X, out other.Y, out other.Z, out other.T);
		Edwards25519.ToCached(in other, out EdwardsCachedPoint cached);
		Edwards25519.Add(in result, in cached, out EdwardsCompletedPoint sum);
		Edwards25519.ToExtended(in sum, out result);
		other.ZeroMemory();
		cached.ZeroMemory();
		sum.ZeroMemory();
	}
}
