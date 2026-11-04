using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Field448TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

internal static class Curve448TestUtils
{
	internal static EdwardsPoint ToPoint(EdwardsValue value, BigInteger z)
	{
		return new EdwardsPoint
		{
			X = Element(value.X * z),
			Y = Element(value.Y * z),
			Z = Element(z),
			T = Element(value.X * value.Y * z),
		};
	}

	internal static EdwardsPoint ToPoint(EdwardsValue value)
	{
		return ToPoint(value, 1);
	}

	// Null if the coordinates are not tight, Z is 0 or XY ≠ ZT.
	internal static EdwardsValue? ToValue(in EdwardsPoint point)
	{
		BigInteger x = ValueOf(point.X);
		BigInteger y = ValueOf(point.Y);
		BigInteger z = Mod(ValueOf(point.Z));
		BigInteger t = ValueOf(point.T);

		if (!IsTight(point.X) || !IsTight(point.Y) || !IsTight(point.Z) || !IsTight(point.T) || z.IsZero || !Mod(x * y - z * t).IsZero)
		{
			return null;
		}

		BigInteger inverse = Inverse(z);
		return new EdwardsValue(Mod(x * inverse), Mod(y * inverse));
	}

	internal static byte[] Scalar(BigInteger value)
	{
		return EncodeInteger(value);
	}

	// Even and odd edge scalars, which the comb recoding tells apart.
	internal static List<BigInteger> Scalars(Random random, int count)
	{
		BigInteger top = (BigInteger.One << 448) - 1;
		List<BigInteger> scalars = [0, 1, 2, 3, 4, L - 1, L, L + 1, 4 * L - 1, 4 * L, BigInteger.One << 446, BigInteger.One << 447, top, top - 1, top - L];

		for (int i = 0; i < count; ++i)
		{
			byte[] clamped = new byte[56];
			random.NextBytes(clamped);
			clamped[0] &= 0xFC;
			clamped[55] |= 0x80;
			scalars.Add(RandomBelow(random, L));
			scalars.Add(DecodeInteger(clamped));
			scalars.Add(RandomBelow(random, top + 1));
		}

		return scalars;
	}

	internal static string Show(EdwardsValue? point)
	{
		return point is { } value ? $"({value.X:X}, {value.Y:X})" : "not a point";
	}
}
