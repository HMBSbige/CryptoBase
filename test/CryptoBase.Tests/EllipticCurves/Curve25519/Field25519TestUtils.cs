using CryptoBase.EllipticCurves.Curve25519;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

internal static class Field25519TestUtils
{
	internal const ulong TightLow = (1UL << 51) + (1UL << 13);

	internal const ulong TightLimb0 = (1UL << 51) + (1UL << 18);

	// The bound on the limbs that Multiply, Square and MultiplySmall take.
	internal const ulong MultiplyBound = 1UL << 54;

	// Every limb at the largest that a tight element allows.
	internal static readonly Field25519 LargestTight = Limbs(TightLimb0 - 1, TightLow - 1, TightLow - 1, TightLow - 1, TightLow - 1);

	internal static BigInteger ValueOf(in Field25519 value)
	{
		return value.L0 + ((BigInteger)value.L1 << 51) + ((BigInteger)value.L2 << 102) + ((BigInteger)value.L3 << 153) + ((BigInteger)value.L4 << 204);
	}

	internal static Field25519 Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
	{
		return new Field25519 { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4 };
	}

	// The canonical limbs of value mod p.
	internal static Field25519 Element(BigInteger value)
	{
		BigInteger v = Mod(value);
		ulong mask = (1UL << 51) - 1;
		return Limbs((ulong)(v & mask), (ulong)(v >> 51 & mask), (ulong)(v >> 102 & mask), (ulong)(v >> 153 & mask), (ulong)(v >> 204));
	}

	internal static bool IsTight(Field25519 value)
	{
		return value.L0 < TightLimb0 && value.L1 < TightLow && value.L2 < TightLow && value.L3 < TightLow && value.L4 < TightLow;
	}

	internal static bool IsCanonical(Field25519 value)
	{
		ulong limit = 1UL << 51;
		return value.L0 < limit && value.L1 < limit && value.L2 < limit && value.L3 < limit && value.L4 < limit && ValueOf(value) < P;
	}

	internal static bool IsBelow(Field25519 value, ulong bound)
	{
		return value.L0 < bound && value.L1 < bound && value.L2 < bound && value.L3 < bound && value.L4 < bound;
	}

	internal static ulong Next(Random random, ulong bound)
	{
		return (ulong)random.NextInt64(long.MinValue, long.MaxValue) % bound;
	}

	// Limbs below bound, each at its most in turn and all at once, then random ones.
	internal static List<Field25519> Elements(Random random, ulong bound, int count)
	{
		ulong most = bound - 1;
		List<Field25519> values = [Limbs(most, most, most, most, most), Limbs(0, 0, 0, 0, 0), Limbs(most, 0, most, 0, most), Limbs(0, most, 0, most, 0)];

		for (int i = 0; i < count; ++i)
		{
			values.Add(Limbs(Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound)));
		}

		return values;
	}

	// Tight elements of values that matter: 0, 1, p − 1, p, p + 1 and 2^255 − 1, and random ones, including their largest tight limbs.
	internal static List<Field25519> TightElements(Random random, int count)
	{
		List<Field25519> values = [Element(0), Element(1), Element(P - 1), Limbs(TightLimb0 - 1, TightLow - 1, TightLow - 1, TightLow - 1, TightLow - 1)];

		foreach (BigInteger special in (BigInteger[])[P, P + 1, (BigInteger.One << 255) - 1])
		{
			ulong mask = (1UL << 51) - 1;
			values.Add(Limbs((ulong)(special & mask), (ulong)(special >> 51 & mask), (ulong)(special >> 102 & mask), (ulong)(special >> 153 & mask), (ulong)(special >> 204)));
		}

		for (int i = 0; i < count; ++i)
		{
			values.Add(Limbs(Next(random, TightLimb0), Next(random, TightLow), Next(random, TightLow), Next(random, TightLow), Next(random, TightLow)));
		}

		return values;
	}

	internal static string Show(in Field25519 value)
	{
		return $"[{value.L0:X}, {value.L1:X}, {value.L2:X}, {value.L3:X}, {value.L4:X}]";
	}
}
