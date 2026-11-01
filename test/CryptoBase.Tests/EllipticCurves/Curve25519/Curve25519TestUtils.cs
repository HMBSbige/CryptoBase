using CryptoBase.EllipticCurves.Curve25519;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Field25519TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

internal static class Curve25519TestUtils
{
	// The point in extended coordinates with the given Z, which must not be 0 mod p.
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

	// The affine point, or null if the coordinates are not tight, Z is 0 or XY ≠ ZT.
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

	// Scalars at the edges of what the multiplications take, and random ones below L, clamped and of all 256 bits.
	internal static List<BigInteger> Scalars(Random random, int count)
	{
		BigInteger top = (BigInteger.One << 256) - 1;
		List<BigInteger> scalars = [0, 1, 2, 3, 8, L - 1, L, L + 1, 8 * L - 1, BigInteger.One << 252, BigInteger.One << 254, (BigInteger.One << 255) - 1, BigInteger.One << 255, top, top - L];

		for (int i = 0; i < count; ++i)
		{
			byte[] clamped = new byte[32];
			random.NextBytes(clamped);
			clamped[0] &= 0xF8;
			clamped[31] = (byte)(clamped[31] & 0x7F | 0x40);
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
