namespace CryptoBase.EllipticCurves.Curve25519;

// The twisted Edwards curve −x² + y² = 1 + dx²y² over the field of p = 2^255 − 19, d = −121665/121666, of order 8L. As −1 is a square and d is not, the addition formulas are complete: they hold for any two points, equal, opposite or of small order alike.
// Nothing here branches on or indexes by a point or a scalar, except where a method says that its inputs must be public. The extended coordinates of a product depend on the scalar and not only on the point, so a caller with a secret scalar clears them once it has the encoding.
// The formulas write a coordinate of the result only after their last read of the inputs, so the result may be an input.
internal static class Edwards25519
{
	internal const int EncodedLength = 32;

	internal const int ScalarLength = 32;

	// d = −121665/121666.
	internal static ref readonly Field25519 D => ref Field25519.FromConstant(DLimbs);

	internal static ref readonly Field25519 TwoD => ref Field25519.FromConstant(TwoDLimbs);

	// B = (x, 4/5) with x even, in extended coordinates with Z = 1.
	internal static ref readonly EdwardsPoint Base => ref Unsafe.As<ulong, EdwardsPoint>(ref MemoryMarshal.GetReference(BaseLimbs));

	private static ReadOnlySpan<ulong> DLimbs => [0x00034DCA135978A3, 0x0001A8283B156EBD, 0x0005E7A26001C029, 0x000739C663A03CBB, 0x00052036CEE2B6FF];

	private static ReadOnlySpan<ulong> TwoDLimbs => [0x00069B9426B2F159, 0x00035050762ADD7A, 0x0003CF44C0038052, 0x0006738CC7407977, 0x0002406D9DC56DFF];

	private static ReadOnlySpan<ulong> BaseLimbs =>
	[
		0x00062D608F25D51A, 0x000412A4B4F6592A, 0x00075B7171A4B31D, 0x0001FF60527118FE, 0x000216936D3CD6E5,
		0x0006666666666658, 0x0004CCCCCCCCCCCC, 0x0001999999999999, 0x0003333333333333, 0x0006666666666666,
		0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x00068AB3A5B7DDA3, 0x00000EEA2A5EADBB, 0x0002AF8DF483C27E, 0x000332B375274732, 0x00067875F0FD78B7,
	];

	// (0 : 1 : 1 : 0).
	internal static void Identity(out EdwardsPoint result)
	{
		result = default;
		result.Y.L0 = 1;
		result.Z.L0 = 1;
	}

	// [s]B for any 32 little-endian bytes s. Neither the time nor the addresses depend on s.
	internal static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarLength);

		Curve25519KernelDispatch.MultiplyBase(scalar, out result);
	}

	// [a]A + [b]B for any 32 little-endian bytes a and b and a point A. The time depends on all three, which must be public.
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Debug.Assert(a.Length is ScalarLength && b.Length is ScalarLength);

		Curve25519KernelDispatch.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
	}

	// As above, with the table that EdwardsVariableTimePointTable builds for A.
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsNielsPoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Debug.Assert(a.Length is ScalarLength && b.Length is ScalarLength);
		Debug.Assert(pointTable.Length == EdwardsVariableTimePointTable.Length);

		Curve25519KernelDispatch.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
	}

	// RFC 8032 §5.1.2: y in 32 little-endian bytes, with the sign of x in bit 255.
	internal static void Encode(in EdwardsPoint point, Span<byte> destination)
	{
		Field25519.Invert(in point.Z, out Field25519 inverse);
		Encode(in point, in inverse, destination);
		inverse.ZeroMemory();
	}

	// As above for a public point: the inversion takes variable time.
	internal static void EncodeVariableTime(in EdwardsPoint point, Span<byte> destination)
	{
		Field25519.InvertVariableTime(in point.Z, out Field25519 inverse);
		Encode(in point, in inverse, destination);
	}

	// RFC 8032 §5.1.3, strictly: false, with result default, for a y of p or more, a y for which x² = (y² − 1)/(dy² + 1) has no root, or x = 0 with the sign bit set. dy² + 1 is never 0, as −1/d is not a square. The checks take constant time, although the input is public.
	internal static bool TryDecode(ReadOnlySpan<byte> source, out EdwardsPoint result)
	{
		if (source.Length is not EncodedLength)
		{
			result = default;
			return false;
		}

		Field25519.FromBytes(source, out Field25519 y);
		ulong sign = 0 - (ulong)(source[EncodedLength - 1] >> 7);
		ulong valid = Field25519.IsBelowModulus(in y);
		Field25519.Square(in y, out Field25519 yy);
		Field25519.Subtract(in yy, in Field25519.One, out Field25519 u);
		Field25519.Carry(in u, out u);
		Field25519.Multiply(in yy, in D, out Field25519 v);
		Field25519.Add(in v, in Field25519.One, out v);
		valid &= Field25519.SqrtRatio(in u, in v, out Field25519 x);
		valid &= ~(Field25519.IsZero(in x) & sign);
		Field25519.ConditionalNegate(Field25519.IsNegative(in x) ^ sign, ref x);

		if (valid is 0)
		{
			result = default;
			return false;
		}

		result.X = x;
		result.Y = y;
		result.Z = Field25519.One;
		Field25519.Multiply(in x, in y, out result.T);
		return true;
	}

	// u = (1 + y)/(1 − y) = (Z + Y)/(Z − Y), the birational map to Curve25519, in 32 little-endian bytes. The identity, where 1 − y = 0, gives 0, as the inversion takes 0 to 0.
	internal static void ToMontgomeryU(in EdwardsPoint point, Span<byte> destination)
	{
		Field25519.Add(in point.Z, in point.Y, out Field25519 numerator);
		Field25519.Subtract(in point.Z, in point.Y, out Field25519 denominator);
		Field25519.Invert(in denominator, out denominator);
		Field25519.Multiply(in numerator, in denominator, out numerator);
		Field25519.ToBytes(in numerator, destination);
		numerator.ZeroMemory();
		denominator.ZeroMemory();
	}

	internal static void Double(in EdwardsPoint value, out EdwardsPoint result)
	{
		Double(in AsProjective(in value), out EdwardsCompletedPoint doubled);
		ToExtended(in doubled, out result);
	}

	// (−X : Y : Z : −T).
	internal static void Negate(in EdwardsPoint value, out EdwardsPoint result)
	{
		result.Y = value.Y;
		result.Z = value.Z;
		Field25519.Negate(in value.X, out result.X);
		Field25519.Negate(in value.T, out result.T);
	}

	internal static void ToCached(in EdwardsPoint value, out EdwardsCachedPoint result)
	{
		Field25519.Add(in value.Y, in value.X, out Field25519 sum);
		Field25519.Subtract(in value.Y, in value.X, out Field25519 difference);
		Field25519.Add(in value.Z, in value.Z, out Field25519 twice);
		Field25519.Multiply(in value.T, in TwoD, out result.TwoDT);
		Field25519.Carry(in sum, out result.YPlusX);
		Field25519.Carry(in difference, out result.YMinusX);
		Field25519.Carry(in twice, out result.TwoZ);
	}

	// A = (Y1 − X1)(Y2 − X2), B = (Y1 + X1)(Y2 + X2), C = T1·2dT2 and D = Z1·2Z2 give x = (B − A)/(D + C) and y = (B + A)/(D − C). A, B, C and D are tight, so the four results are below 2^53.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void Add(in EdwardsPoint left, in EdwardsCachedPoint right, out EdwardsCompletedPoint result)
	{
		Field25519.Add(in left.Y, in left.X, out Field25519 sum);
		Field25519.Subtract(in left.Y, in left.X, out Field25519 difference);
		Field25519.MultiplyCore(in sum, in right.YPlusX, out Field25519 b);
		Field25519.MultiplyCore(in difference, in right.YMinusX, out Field25519 a);
		Field25519.MultiplyCore(in left.T, in right.TwoDT, out Field25519 c);
		Field25519.MultiplyCore(in left.Z, in right.TwoZ, out Field25519 d);
		Field25519.Subtract(in b, in a, out result.X);
		Field25519.Add(in b, in a, out result.Y);
		Field25519.Add(in d, in c, out result.Z);
		Field25519.Subtract(in d, in c, out result.T);
	}

	// As Add with the right operand negated, (Y − X, Y + X, 2Z, −2dT).
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void Subtract(in EdwardsPoint left, in EdwardsCachedPoint right, out EdwardsCompletedPoint result)
	{
		Field25519.Add(in left.Y, in left.X, out Field25519 sum);
		Field25519.Subtract(in left.Y, in left.X, out Field25519 difference);
		Field25519.MultiplyCore(in sum, in right.YMinusX, out Field25519 b);
		Field25519.MultiplyCore(in difference, in right.YPlusX, out Field25519 a);
		Field25519.MultiplyCore(in left.T, in right.TwoDT, out Field25519 c);
		Field25519.MultiplyCore(in left.Z, in right.TwoZ, out Field25519 d);
		Field25519.Subtract(in b, in a, out result.X);
		Field25519.Add(in b, in a, out result.Y);
		Field25519.Subtract(in d, in c, out result.Z);
		Field25519.Add(in d, in c, out result.T);
	}

	// As Add with an affine right, Z2 = 1, so D = 2Z1 needs no product; D is below 2^53 and the results below 2^53.1.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void AddNiels(in EdwardsPoint left, in EdwardsNielsPoint right, out EdwardsCompletedPoint result)
	{
		Field25519.Add(in left.Y, in left.X, out Field25519 sum);
		Field25519.Subtract(in left.Y, in left.X, out Field25519 difference);
		Field25519.MultiplyCore(in sum, in right.YPlusX, out Field25519 b);
		Field25519.MultiplyCore(in difference, in right.YMinusX, out Field25519 a);
		Field25519.MultiplyCore(in left.T, in right.TwoDXY, out Field25519 c);
		Field25519.Add(in left.Z, in left.Z, out Field25519 d);
		Field25519.Subtract(in b, in a, out result.X);
		Field25519.Add(in b, in a, out result.Y);
		Field25519.Add(in d, in c, out result.Z);
		Field25519.Subtract(in d, in c, out result.T);
	}

	// As AddNiels with the right operand negated, (y − x, y + x, −2dxy).
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void SubtractNiels(in EdwardsPoint left, in EdwardsNielsPoint right, out EdwardsCompletedPoint result)
	{
		Field25519.Add(in left.Y, in left.X, out Field25519 sum);
		Field25519.Subtract(in left.Y, in left.X, out Field25519 difference);
		Field25519.MultiplyCore(in sum, in right.YMinusX, out Field25519 b);
		Field25519.MultiplyCore(in difference, in right.YPlusX, out Field25519 a);
		Field25519.MultiplyCore(in left.T, in right.TwoDXY, out Field25519 c);
		Field25519.Add(in left.Z, in left.Z, out Field25519 d);
		Field25519.Subtract(in b, in a, out result.X);
		Field25519.Add(in b, in a, out result.Y);
		Field25519.Subtract(in d, in c, out result.Z);
		Field25519.Add(in d, in c, out result.T);
	}

	// x = 2XY/(Y² − X²) and y = (Y² + X²)/(2Z² − Y² + X²), with 2XY = (X + Y)² − Y² − X². The two differences take 4p, as their right operands are sums or differences of two squares; the results are below 2^53.6.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	internal static void Double(in EdwardsProjectivePoint value, out EdwardsCompletedPoint result)
	{
		Field25519.SquareCore(in value.X, out Field25519 xx);
		Field25519.SquareCore(in value.Y, out Field25519 yy);
		Field25519.SquareCore(in value.Z, out Field25519 zz);
		Field25519.Add(in value.X, in value.Y, out Field25519 sum);
		Field25519.SquareCore(in sum, out sum);
		Field25519.Add(in zz, in zz, out zz);
		Field25519.Add(in yy, in xx, out result.Y);
		Field25519.Subtract(in yy, in xx, out result.Z);
		Field25519.SubtractFromFourP(in sum, in result.Y, out result.X);
		Field25519.SubtractFromFourP(in zz, in result.Z, out result.T);
	}

	// Where Field25519.MultiplyCore inlines its products, the four of them go into a method of their own rather than into each caller; elsewhere they are four calls, made from the caller directly. Only that method sets outOfLine.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ToExtended(in EdwardsCompletedPoint value, out EdwardsPoint result, bool outOfLine = false)
	{
		if (!outOfLine && (Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported))
		{
			ToExtendedOutOfLine(in value, out result);
			return;
		}

		Field25519.MultiplyCore(in value.X, in value.T, out Field25519 x);
		Field25519.MultiplyCore(in value.Y, in value.Z, out Field25519 y);
		Field25519.MultiplyCore(in value.Z, in value.T, out Field25519 z);
		Field25519.MultiplyCore(in value.X, in value.Y, out result.T);
		result.X = x;
		result.Y = y;
		result.Z = z;
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ToExtendedOutOfLine(in EdwardsCompletedPoint value, out EdwardsPoint result)
	{
		ToExtended(in value, out result, true);
	}

	// As ToExtended, with three products.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ToProjective(in EdwardsCompletedPoint value, out EdwardsProjectivePoint result, bool outOfLine = false)
	{
		if (!outOfLine && (Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported))
		{
			ToProjectiveOutOfLine(in value, out result);
			return;
		}

		Field25519.MultiplyCore(in value.X, in value.T, out Field25519 x);
		Field25519.MultiplyCore(in value.Y, in value.Z, out Field25519 y);
		Field25519.MultiplyCore(in value.Z, in value.T, out result.Z);
		result.X = x;
		result.Y = y;
	}

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static void ToProjectiveOutOfLine(in EdwardsCompletedPoint value, out EdwardsProjectivePoint result)
	{
		ToProjective(in value, out result, true);
	}

	// The first three coordinates of a point in extended coordinates, read in place.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly EdwardsProjectivePoint AsProjective(ref readonly EdwardsPoint value)
	{
		return ref Unsafe.As<EdwardsPoint, EdwardsProjectivePoint>(ref Unsafe.AsRef(in value));
	}

	// Sets result[i] to (y + x, y − x, 2dxy) of points[i], with one inversion for all of them: result[i].YPlusX holds the product of the Z of points 0 to i until result[i] is written. The points must be public, as the inversion takes variable time.
	internal static void ToNielsVariableTime(ReadOnlySpan<EdwardsPoint> points, Span<EdwardsNielsPoint> result)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		result[0].YPlusX = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			Field25519.Multiply(in result[i - 1].YPlusX, in points[i].Z, out result[i].YPlusX);
		}

		Field25519.InvertVariableTime(in result[^1].YPlusX, out Field25519 inverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			Field25519.Multiply(in inverse, in result[i - 1].YPlusX, out Field25519 zInverse);
			Field25519.Multiply(in inverse, in points[i].Z, out inverse);
			ToNiels(in points[i], in zInverse, out result[i]);
		}

		ToNiels(in points[0], in inverse, out result[0]);
	}

	// (y + x, y − x, 2dxy) of a point from zInverse = 1/Z.
	private static void ToNiels(in EdwardsPoint point, in Field25519 zInverse, out EdwardsNielsPoint result)
	{
		Field25519.Multiply(in point.X, in zInverse, out Field25519 x);
		Field25519.Multiply(in point.Y, in zInverse, out Field25519 y);
		Field25519.Add(in y, in x, out Field25519 sum);
		Field25519.Subtract(in y, in x, out Field25519 difference);
		Field25519.Multiply(in x, in y, out x);
		Field25519.Multiply(in x, in TwoD, out result.TwoDXY);
		Field25519.Carry(in sum, out result.YPlusX);
		Field25519.Carry(in difference, out result.YMinusX);
	}

	// Encodes with inverse = 1/Z.
	private static void Encode(in EdwardsPoint point, in Field25519 inverse, Span<byte> destination)
	{
		Debug.Assert(destination.Length is EncodedLength);

		Field25519.Multiply(in point.X, in inverse, out Field25519 x);
		Field25519.Multiply(in point.Y, in inverse, out Field25519 y);
		Field25519.ToBytes(in y, destination);
		destination[EncodedLength - 1] |= (byte)(Field25519.IsNegative(in x) & 0x80);
		x.ZeroMemory();
		y.ZeroMemory();
	}
}
