namespace CryptoBase.EllipticCurves.Curve448;

// The Edwards curve edwards448, x² + y² = 1 + dx²y² over the field of p = 2^448 − 2^224 − 1, d = −39081, of order 4L (RFC 8032 §5.2). As 1 is a square and d is not, the addition formulas are complete: they hold for any two points, equal, opposite or of small order alike.
// Nothing here branches on or indexes by a point or a scalar, except where a method says that its inputs must be public. The extended coordinates of a product depend on the scalar and not only on the point, so a caller with a secret scalar clears them once it has the encoding.
// The formulas write a coordinate of the result only after their last read of the inputs, so the result may be an input. In the bounds below, a limb bound of m means m·2^56: a tight element has 1, a sum of two 2 and a difference 3.
internal static class Edwards448
{
	internal const int EncodedLength = 57;

	internal const int ScalarLength = 56;

	// −d, the multiplier of MultiplySmall whose product the formulas negate.
	internal const uint MinusD = 39081;

	// B = (x, y) of RFC 8032 §5.2 in extended coordinates with Z = 1.
	internal static ref readonly EdwardsPoint Base => ref Unsafe.As<ulong, EdwardsPoint>(ref MemoryMarshal.GetReference(BaseLimbs));

	private static ReadOnlySpan<ulong> BaseLimbs =>
	[
		0x0026A82BC70CC05E, 0x0080E18B00938E26, 0x00F72AB66511433B, 0x00A3D3A46412AE1A, 0x000F1767EA6DE324, 0x0036DA9E14657047, 0x00ED221D15A622BF, 0x004F1970C66BED0D,
		0x0008795BF230FA14, 0x00132C4ED7C8AD98, 0x001CE67C39C4FDBD, 0x0005A0C2D73AD3FF, 0x00A3984087789C1E, 0x00C7624BEA73736C, 0x00248876203756C9, 0x00693F46716EB6BC,
		0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0006624E82AF95F3, 0x00A07D85662D1DEB, 0x0090B5B27DA1F78F, 0x00E2356D58F179DE, 0x008451D260D71667, 0x0091C9C5056A183F, 0x006CCEC39D2D508D, 0x00C75EB58AEE221C,
	];

	// (0 : 1 : 1 : 0).
	internal static void Identity(out EdwardsPoint result)
	{
		result = default;
		result.Y.L0 = 1;
		result.Z.L0 = 1;
	}

	// [s]B for any 56 little-endian bytes s. Neither the time nor the addresses depend on s.
	internal static void MultiplyBase(ReadOnlySpan<byte> scalar, out EdwardsPoint result)
	{
		Debug.Assert(scalar.Length is ScalarLength);

		Curve448KernelDispatch.MultiplyBase(scalar, out result);
	}

	// [a]A + [b]B for any 56 little-endian bytes a and b and any point A, whatever its order. The time depends on all three, which must be public.
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, in EdwardsPoint point, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Debug.Assert(a.Length is ScalarLength && b.Length is ScalarLength);

		Curve448KernelDispatch.DoubleScalarMultiplyVariableTime(a, in point, b, out result);
	}

	// As above, with the table that EdwardsVariableTimePointTable builds for A.
	internal static void DoubleScalarMultiplyVariableTime(ReadOnlySpan<byte> a, ReadOnlySpan<EdwardsAffinePoint> pointTable, ReadOnlySpan<byte> b, out EdwardsPoint result)
	{
		Debug.Assert(a.Length is ScalarLength && b.Length is ScalarLength);
		Debug.Assert(pointTable.Length == EdwardsVariableTimePointTable.Length);

		Curve448KernelDispatch.DoubleScalarMultiplyVariableTime(a, pointTable, b, out result);
	}

	// RFC 8032 §5.2.2: y in 56 little-endian bytes, then a byte with the sign of x in its top bit.
	internal static void Encode(in EdwardsPoint point, Span<byte> destination)
	{
		Field448.Invert(in point.Z, out Field448 inverse);
		Encode(in point, in inverse, destination);
		inverse.ZeroMemory();
	}

	// As above for a public point: the inversion takes variable time.
	internal static void EncodeVariableTime(in EdwardsPoint point, Span<byte> destination)
	{
		Field448.InvertVariableTime(in point.Z, out Field448 inverse);
		Encode(in point, in inverse, destination);
	}

	// RFC 8032 §5.2.3, strictly: false, with result default, for the wrong length, a y of p or more, any of the low seven bits of the last byte set, a y for which x² = (y² − 1)/(dy² − 1) has no root, or x = 0 with the sign bit set. dy² − 1 is never 0, as d is not a square. The checks take constant time, although the input is public.
	internal static bool TryDecode(ReadOnlySpan<byte> source, out EdwardsPoint result)
	{
		if (source.Length is not EncodedLength)
		{
			result = default;
			return false;
		}

		Field448.FromBytes(source.Slice(0, Field448.ByteLength), out Field448 y);
		byte last = source[EncodedLength - 1];
		ulong sign = 0 - (ulong)(last >> 7);
		ulong valid = Field448.IsBelowModulus(in y) & LimbArithmetic.ZeroMask((uint)last & 0x7F);
		Field448.Square(in y, out Field448 yy);
		Field448.Subtract(in yy, in Field448.One, out Field448 u);
		Field448.Carry(in u, out u);
		// dy² − 1 = −(39081·y² + 1); MultiplySmall leaves limb 0 below 2^56 + 2^8, so adding 1 keeps it tight.
		Field448.MultiplySmall(in yy, MinusD, out Field448 v);
		++v.L0;
		Field448.Negate(in v, out v);
		valid &= Field448.SqrtRatio(in u, in v, out Field448 x);
		valid &= ~(Field448.IsZero(in x) & sign);
		Field448.ConditionalNegate(Field448.IsNegative(in x) ^ sign, ref x);

		if (valid is 0)
		{
			result = default;
			return false;
		}

		result.X = x;
		result.Y = y;
		result.Z = Field448.One;
		Field448.Multiply(in x, in y, out result.T);
		return true;
	}

	// u = y²/x² = (Y/X)², the 4-isogeny of RFC 7748 §4.2 to Curve448, which takes B to u = 5, in 56 little-endian bytes. A point with x = 0, the identity or the point of order 2, gives 0, as the inversion takes 0 to 0, and so does the ladder for the point at infinity that the isogeny gives for them.
	internal static void ToMontgomeryU(in EdwardsPoint point, Span<byte> destination)
	{
		Field448.Invert(in point.X, out Field448 inverse);
		Field448.Multiply(in point.Y, in inverse, out inverse);
		Field448.Square(in inverse, out inverse);
		Field448.ToBytes(in inverse, destination);
		inverse.ZeroMemory();
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
		Field448.Negate(in value.X, out result.X);
		Field448.Negate(in value.T, out result.T);
	}

	// dT = −39081·T.
	internal static void ToCached(in EdwardsPoint value, out EdwardsCachedPoint result)
	{
		Field448.MultiplySmall(in value.T, MinusD, out Field448 scaled);
		result.X = value.X;
		result.Y = value.Y;
		result.Z = value.Z;
		Field448.Negate(in scaled, out result.DT);
	}

	// A = X1X2, B = Y1Y2, C = T1·dT2 and D = Z1Z2 give x = E/(D + C) and y = (B − A)/(D − C) with E = (X1 + Y1)(X2 + Y2) − A − B = X1Y2 + Y1X2. E takes 4p and a carry, which leaves it at 1; B − A and D − C are at 3 and D + C at 2, so each product of ToExtended is at most 6.
	internal static void Add(in EdwardsPoint left, in EdwardsCachedPoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.X, in left.Y, out Field448 leftSum);
		Field448.Add(in right.X, in right.Y, out Field448 rightSum);
		Field448.Multiply(in leftSum, in rightSum, out Field448 e);
		Field448.Multiply(in left.X, in right.X, out Field448 a);
		Field448.Multiply(in left.Y, in right.Y, out Field448 b);
		Field448.Multiply(in left.T, in right.DT, out Field448 c);
		Field448.Multiply(in left.Z, in right.Z, out Field448 d);
		Field448.Add(in a, in b, out Field448 ab);
		Field448.SubtractFromFourP(in e, in ab, out e);
		Field448.Carry(in e, out result.X);
		Field448.Subtract(in b, in a, out result.Y);
		Field448.Add(in d, in c, out result.Z);
		Field448.Subtract(in d, in c, out result.T);
	}

	// As Add with the right operand negated, (−X, Y, Z, −dT): with A = X1X2 and C = T1·dT2 as products of the unnegated operand, E = (X1 + Y1)(Y2 − X2) + A − B, at 4 before its carry, x = E/(D − C) and y = (B + A)/(D + C). (X1 + Y1)(Y2 − X2) is a product at 2 by 3, and the products of ToExtended stay at 6.
	internal static void Subtract(in EdwardsPoint left, in EdwardsCachedPoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.X, in left.Y, out Field448 leftSum);
		Field448.Subtract(in right.Y, in right.X, out Field448 rightDifference);
		Field448.Multiply(in leftSum, in rightDifference, out Field448 e);
		Field448.Multiply(in left.X, in right.X, out Field448 a);
		Field448.Multiply(in left.Y, in right.Y, out Field448 b);
		Field448.Multiply(in left.T, in right.DT, out Field448 c);
		Field448.Multiply(in left.Z, in right.Z, out Field448 d);
		Field448.Add(in e, in a, out e);
		Field448.Subtract(in e, in b, out e);
		Field448.Carry(in e, out result.X);
		Field448.Add(in b, in a, out result.Y);
		Field448.Subtract(in d, in c, out result.Z);
		Field448.Add(in d, in c, out result.T);
	}

	// As Add with an affine right, Z2 = 1, so D = Z1 needs no product, and T2 = xy: four products instead of five.
	internal static void AddAffine(in EdwardsPoint left, in EdwardsAffinePoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.X, in left.Y, out Field448 leftSum);
		Field448.Add(in right.X, in right.Y, out Field448 rightSum);
		Field448.Multiply(in leftSum, in rightSum, out Field448 e);
		Field448.Multiply(in left.X, in right.X, out Field448 a);
		Field448.Multiply(in left.Y, in right.Y, out Field448 b);
		Field448.Multiply(in left.T, in right.DXY, out Field448 c);
		Field448.Add(in a, in b, out Field448 ab);
		Field448.SubtractFromFourP(in e, in ab, out e);
		Field448.Carry(in e, out result.X);
		Field448.Subtract(in b, in a, out result.Y);
		Field448.Add(in left.Z, in c, out result.Z);
		Field448.Subtract(in left.Z, in c, out result.T);
	}

	// As Subtract with an affine right, (−x, y, −dxy).
	internal static void SubtractAffine(in EdwardsPoint left, in EdwardsAffinePoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.X, in left.Y, out Field448 leftSum);
		Field448.Subtract(in right.Y, in right.X, out Field448 rightDifference);
		Field448.Multiply(in leftSum, in rightDifference, out Field448 e);
		Field448.Multiply(in left.X, in right.X, out Field448 a);
		Field448.Multiply(in left.Y, in right.Y, out Field448 b);
		Field448.Multiply(in left.T, in right.DXY, out Field448 c);
		Field448.Add(in e, in a, out e);
		Field448.Subtract(in e, in b, out e);
		Field448.Carry(in e, out result.X);
		Field448.Add(in b, in a, out result.Y);
		Field448.Subtract(in left.Z, in c, out result.Z);
		Field448.Add(in left.Z, in c, out result.T);
	}

	// x = 2XY/(X² + Y²) and y = (Y² − X²)/(2Z² − X² − Y²), with 2XY = (X + Y)² − X² − Y². The differences from X² + Y², at 2, take 4p: 2XY, at 5, is carried, and 2Z² − X² − Y² stays at 6, which ToExtended multiplies by 1 and by X² + Y² at 2.
	internal static void Double(in EdwardsProjectivePoint value, out EdwardsCompletedPoint result)
	{
		Field448.Add(in value.X, in value.Y, out Field448 sum);
		Field448.Square(in sum, out sum);
		Field448.Square(in value.X, out Field448 xx);
		Field448.Square(in value.Y, out Field448 yy);
		Field448.Square(in value.Z, out Field448 zz);
		Field448.Add(in zz, in zz, out zz);
		Field448.Add(in xx, in yy, out result.Z);
		Field448.Subtract(in yy, in xx, out result.Y);
		Field448.SubtractFromFourP(in sum, in result.Z, out sum);
		Field448.Carry(in sum, out result.X);
		Field448.SubtractFromFourP(in zz, in result.Z, out result.T);
	}

	// (XT : YZ : ZT : XY).
	internal static void ToExtended(in EdwardsCompletedPoint value, out EdwardsPoint result)
	{
		Field448.Multiply(in value.X, in value.T, out Field448 x);
		Field448.Multiply(in value.Y, in value.Z, out Field448 y);
		Field448.Multiply(in value.Z, in value.T, out Field448 z);
		Field448.Multiply(in value.X, in value.Y, out result.T);
		result.X = x;
		result.Y = y;
		result.Z = z;
	}

	// As ToExtended, with three products.
	internal static void ToProjective(in EdwardsCompletedPoint value, out EdwardsProjectivePoint result)
	{
		Field448.Multiply(in value.X, in value.T, out Field448 x);
		Field448.Multiply(in value.Y, in value.Z, out Field448 y);
		Field448.Multiply(in value.Z, in value.T, out result.Z);
		result.X = x;
		result.Y = y;
	}

	// The first three coordinates of a point in extended coordinates, read in place.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref readonly EdwardsProjectivePoint AsProjective(ref readonly EdwardsPoint value)
	{
		return ref Unsafe.As<EdwardsPoint, EdwardsProjectivePoint>(ref Unsafe.AsRef(in value));
	}

	// Sets result[i] to (x, y, dxy) of points[i], with one inversion for all of them: result[i].X holds the product of the Z of points 0 to i until result[i] is written. The points must be public, as the inversion takes variable time.
	internal static void ToAffineVariableTime(ReadOnlySpan<EdwardsPoint> points, Span<EdwardsAffinePoint> result)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		result[0].X = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			Field448.Multiply(in result[i - 1].X, in points[i].Z, out result[i].X);
		}

		Field448.InvertVariableTime(in result[^1].X, out Field448 inverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			Field448.Multiply(in inverse, in result[i - 1].X, out Field448 zInverse);
			Field448.Multiply(in inverse, in points[i].Z, out inverse);
			ToAffine(in points[i], in zInverse, out result[i]);
		}

		ToAffine(in points[0], in inverse, out result[0]);
	}

	// (x, y, dxy) of a point from zInverse = 1/Z.
	private static void ToAffine(in EdwardsPoint point, in Field448 zInverse, out EdwardsAffinePoint result)
	{
		Field448.Multiply(in point.X, in zInverse, out Field448 x);
		Field448.Multiply(in point.Y, in zInverse, out result.Y);
		Field448.Multiply(in x, in result.Y, out Field448 xy);
		Field448.MultiplySmall(in xy, MinusD, out xy);
		Field448.Negate(in xy, out result.DXY);
		result.X = x;
	}

	// Encodes with inverse = 1/Z.
	private static void Encode(in EdwardsPoint point, in Field448 inverse, Span<byte> destination)
	{
		Debug.Assert(destination.Length is EncodedLength);

		Field448.Multiply(in point.X, in inverse, out Field448 x);
		Field448.Multiply(in point.Y, in inverse, out Field448 y);
		Field448.ToBytes(in y, destination.Slice(0, Field448.ByteLength));
		destination[EncodedLength - 1] = (byte)(Field448.IsNegative(in x) & 0x80);
		x.ZeroMemory();
		y.ZeroMemory();
	}
}
