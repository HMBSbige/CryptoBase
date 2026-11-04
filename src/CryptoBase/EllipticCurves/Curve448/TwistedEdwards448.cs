namespace CryptoBase.EllipticCurves.Curve448;

// The twisted curve −x² + y² = 1 + d'x²y², d' = d − 1 = −39082, which is 4-isogenous to edwards448: Twist, (x, y) ↦ (2xy/(y² − x²), (y² + x²)/(2 − y² − x²)), takes edwards448 to it and Untwist, (x, y) ↦ (2xy/(x² + y²), (y² − x²)/(2 − y² + x²)), takes it back, and either composition is multiplication by 4. Base = [1/4 mod L]·Twist(B), so Untwist([s]Base) = [s]B for every s. Its a = −1 saves a product in each addition and fills the four lanes of a vector kernel.
// The formulas are not complete here, as −1 is not a square, but they are exact unless P1 + P2 or P1 − P2 is one of the points at infinity of the curve, which have order 2 or 4 (Bernstein and Lange, "A complete set of addition laws for incomplete Edwards curves", 2011; Hisil, Wong, Carter and Dawson, "Twisted Edwards curves revisited", 2008, §3). The fixed-base product meets only multiples of Base, of odd order L, so it never meets them; the same holds for the denominators of Untwist, x² + y², which is never 0 as −1 is not a square, and 2 − y² + x² = 1 − d'x²y², that of a doubling.
// Points use the extended coordinates of EdwardsPoint. In the bounds below, a limb bound of m means m·2^56, as in Edwards448.
internal static class TwistedEdwards448
{
	// −2d', the multiplier of MultiplySmall whose product the formulas negate.
	private const uint MinusTwoD = 78164;

	internal static ref readonly EdwardsPoint Base => ref Unsafe.As<ulong, EdwardsPoint>(ref MemoryMarshal.GetReference(BaseLimbs));

	private static ReadOnlySpan<ulong> BaseLimbs =>
	[
		0x000C0F019124548E, 0x003254E364B14F53, 0x00CBF5B7D49822B2, 0x002134DA9EA3B629, 0x00FD3303256706F4, 0x002CF3169D70108C, 0x00334F4B749A1D6D, 0x00A50DD973D99E99,
		0x00838DDC898C408B, 0x006AA966CC6A2FD3, 0x0019C906577BB5ED, 0x00ECFBF89B8465CF, 0x00779FCD525294C2, 0x00CD7F622D842437, 0x00F775C24AB64DFE, 0x00A2A35D8C3CBF45,
		0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x00B570EB800EB906, 0x0059CCF727CA837F, 0x0078CA04585B0A97, 0x004334B4AF25C669, 0x00A7E5D7CF7065D1, 0x00F75A765A1F8473, 0x00CD5DDAEAD5F808, 0x005B1BEDD06A818D,
	];

	// A = (Y1 − X1)(y − x), B = (Y1 + X1)(y + x), C = T1·2d'xy and D = 2Z1 give x = (B − A)/(D + C) and y = (B + A)/(D − C). B − A and D + C are at 3 and D − C at 4, whose products by each other, the largest of ToExtended, are within the 12.25 that Multiply takes.
	internal static void AddNiels(in EdwardsPoint left, in TwistedNielsPoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.Y, in left.X, out Field448 sum);
		Field448.Subtract(in left.Y, in left.X, out Field448 difference);
		Field448.Multiply(in sum, in right.YPlusX, out Field448 b);
		Field448.Multiply(in difference, in right.YMinusX, out Field448 a);
		Field448.Multiply(in left.T, in right.TwoDXY, out Field448 c);
		Field448.Add(in left.Z, in left.Z, out Field448 d);
		Field448.Subtract(in b, in a, out result.X);
		Field448.Add(in b, in a, out result.Y);
		Field448.Add(in d, in c, out result.Z);
		Field448.Subtract(in d, in c, out result.T);
	}

	// (Y + X, Y − X, 2Z, 2d'T), carried, the right operand of Add.
	internal static void ToCached(in EdwardsPoint value, out TwistedCachedPoint result)
	{
		Field448.Add(in value.Y, in value.X, out Field448 sum);
		Field448.Subtract(in value.Y, in value.X, out Field448 difference);
		Field448.Add(in value.Z, in value.Z, out Field448 twice);
		Field448.MultiplySmall(in value.T, MinusTwoD, out Field448 scaled);
		Field448.Carry(in sum, out result.YPlusX);
		Field448.Carry(in difference, out result.YMinusX);
		Field448.Carry(in twice, out result.TwoZ);
		Field448.Negate(in scaled, out result.TwoDT);
	}

	// As AddNiels with D = Z1·2Z2 from a cached right; D + C is at 2 and D − C at 3.
	internal static void Add(in EdwardsPoint left, in TwistedCachedPoint right, out EdwardsCompletedPoint result)
	{
		Field448.Add(in left.Y, in left.X, out Field448 sum);
		Field448.Subtract(in left.Y, in left.X, out Field448 difference);
		Field448.Multiply(in sum, in right.YPlusX, out Field448 b);
		Field448.Multiply(in difference, in right.YMinusX, out Field448 a);
		Field448.Multiply(in left.T, in right.TwoDT, out Field448 c);
		Field448.Multiply(in left.Z, in right.TwoZ, out Field448 d);
		Field448.Subtract(in b, in a, out result.X);
		Field448.Add(in b, in a, out result.Y);
		Field448.Add(in d, in c, out result.Z);
		Field448.Subtract(in d, in c, out result.T);
	}

	// x = 2XY/(Y² − X²) and y = (Y² + X²)/(2Z² − Y² + X²), with 2XY = (X + Y)² − Y² − X². 2XY and 2Z² − Y² + X² take 4p and a carry each, which leaves the products of ToExtended at most 6, Y² + X² at 2 by Y² − X² at 3.
	internal static void Double(in EdwardsProjectivePoint value, out EdwardsCompletedPoint result)
	{
		Field448.Add(in value.X, in value.Y, out Field448 sum);
		Field448.Square(in sum, out sum);
		Field448.Square(in value.X, out Field448 xx);
		Field448.Square(in value.Y, out Field448 yy);
		Field448.Square(in value.Z, out Field448 zz);
		Field448.Add(in zz, in zz, out zz);
		Field448.Add(in yy, in xx, out result.Y);
		Field448.Subtract(in yy, in xx, out result.Z);
		Field448.SubtractFromFourP(in sum, in result.Y, out sum);
		Field448.Carry(in sum, out result.X);
		Field448.SubtractFromFourP(in zz, in result.Z, out zz);
		Field448.Carry(in zz, out result.T);
	}

	// Untwist of a point in projective coordinates, as a point of edwards448: x = 2XY/(X² + Y²) and y = (Y² − X²)/(2Z² − Y² + X²), with 2XY as in Double. 2XY takes 4p and a carry, and 2Z² − (Y² − X²) stays at 6, which ToExtended multiplies by 1 and by X² + Y² at 2.
	internal static void Untwist(in EdwardsProjectivePoint value, out EdwardsCompletedPoint result)
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
		Field448.SubtractFromFourP(in zz, in result.Y, out result.T);
	}

	// (4x : 4y : 4 : 4xy) from (y + x, y − x, 2d'xy): the difference and the sum of the first two are 2x and 2y, their product is 4xy, and their doubles are 4x and 4y.
	internal static void FromNiels(in TwistedNielsPoint point, out EdwardsPoint result)
	{
		Field448.Subtract(in point.YPlusX, in point.YMinusX, out Field448 twoX);
		Field448.Add(in point.YPlusX, in point.YMinusX, out Field448 twoY);
		Field448.Multiply(in twoX, in twoY, out result.T);
		Field448.Add(in twoX, in twoX, out twoX);
		Field448.Add(in twoY, in twoY, out twoY);
		Field448.Carry(in twoX, out result.X);
		Field448.Carry(in twoY, out result.Y);
		result.Z = default;
		result.Z.L0 = 4;
		twoX.ZeroMemory();
		twoY.ZeroMemory();
	}

	// Sets result[i] to (y + x, y − x, 2d'xy) of points[i], each canonical, with one inversion for all of them: result[i].YPlusX holds the product of the Z of points 0 to i until result[i] is written. The points must be public, as the inversion takes variable time.
	internal static void ToNielsVariableTime(ReadOnlySpan<EdwardsPoint> points, Span<TwistedNielsPoint> result)
	{
		Debug.Assert(points.Length > 0 && result.Length == points.Length);

		result[0].YPlusX = points[0].Z;

		for (int i = 1; i < points.Length; ++i)
		{
			Field448.Multiply(in result[i - 1].YPlusX, in points[i].Z, out result[i].YPlusX);
		}

		Field448.InvertVariableTime(in result[^1].YPlusX, out Field448 inverse);

		for (int i = points.Length - 1; i > 0; --i)
		{
			Field448.Multiply(in inverse, in result[i - 1].YPlusX, out Field448 zInverse);
			Field448.Multiply(in inverse, in points[i].Z, out inverse);
			ToNiels(in points[i], in zInverse, out result[i]);
		}

		ToNiels(in points[0], in inverse, out result[0]);
	}

	// (y + x, y − x, 2d'xy) of a point from zInverse = 1/Z.
	private static void ToNiels(in EdwardsPoint point, in Field448 zInverse, out TwistedNielsPoint result)
	{
		Field448.Multiply(in point.X, in zInverse, out Field448 x);
		Field448.Multiply(in point.Y, in zInverse, out Field448 y);
		Field448.Add(in y, in x, out Field448 sum);
		Field448.Subtract(in y, in x, out Field448 difference);
		Field448.Multiply(in x, in y, out x);
		Field448.MultiplySmall(in x, MinusTwoD, out x);
		Field448.Negate(in x, out x);
		Field448.Reduce(in sum, out result.YPlusX);
		Field448.Reduce(in difference, out result.YMinusX);
		Field448.Reduce(in x, out result.TwoDXY);
	}
}
