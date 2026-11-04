using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

internal static class Field448TestUtils
{
	internal const ulong Tight = (1UL << 56) + (1UL << 9);

	// Also the bound of Multiply on both sides.
	internal const ulong SquareBound = 7UL << 55;

	internal static readonly Field448 LargestTight = Limbs(Tight - 1, Tight - 1, Tight - 1, Tight - 1, Tight - 1, Tight - 1, Tight - 1, Tight - 1);

	internal static BigInteger ValueOf(in Field448 value)
	{
		BigInteger result = BigInteger.Zero;

		foreach (ulong limb in LimbsOf(value).Reverse())
		{
			result = (result << 56) + limb;
		}

		return result;
	}

	internal static ulong[] LimbsOf(in Field448 value)
	{
		return [value.L0, value.L1, value.L2, value.L3, value.L4, value.L5, value.L6, value.L7];
	}

	internal static Field448 Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4, ulong l5, ulong l6, ulong l7)
	{
		return new Field448 { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4, L5 = l5, L6 = l6, L7 = l7 };
	}

	internal static Field448 Limbs(ulong[] limbs)
	{
		return Limbs(limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7]);
	}

	internal static Field448 Split(BigInteger value)
	{
		ulong mask = (1UL << 56) - 1;
		ulong[] limbs = new ulong[8];

		for (int i = 0; i < 8; ++i)
		{
			limbs[i] = (ulong)(value >> 56 * i & mask);
		}

		return Limbs(limbs);
	}

	internal static Field448 Element(BigInteger value)
	{
		return Split(Mod(value));
	}

	internal static bool IsTight(Field448 value)
	{
		return IsBelow(value, Tight);
	}

	internal static bool IsCanonical(Field448 value)
	{
		return IsBelow(value, 1UL << 56) && ValueOf(value) < P;
	}

	internal static bool IsBelow(Field448 value, ulong bound)
	{
		return LimbsOf(value).All(limb => limb < bound);
	}

	internal static bool IsWithin(in Field448 value, ulong[] bound)
	{
		return LimbsOf(value).Select((limb, i) => limb <= bound[i]).All(static within => within);
	}

	internal static ulong Next(Random random, ulong bound)
	{
		return (ulong)random.NextInt64(long.MinValue, long.MaxValue) % bound;
	}

	internal static List<Field448> Elements(Random random, ulong bound, int count)
	{
		ulong most = bound - 1;
		List<Field448> values = [Limbs(most, most, most, most, most, most, most, most), Limbs(0, 0, 0, 0, 0, 0, 0, 0), Limbs(most, 0, most, 0, most, 0, most, 0), Limbs(0, most, 0, most, 0, most, 0, most)];

		for (int i = 0; i < count; ++i)
		{
			values.Add(Limbs(Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound), Next(random, bound)));
		}

		return values;
	}

	internal static List<Field448> TightElements(Random random, int count)
	{
		List<Field448> values = [Element(0), Element(1), Element(P - 1), Split(P), Split(P + 1), Split((BigInteger.One << 448) - 1), LargestTight];

		for (int i = 0; i < count; ++i)
		{
			values.Add(Limbs(Next(random, Tight), Next(random, Tight), Next(random, Tight), Next(random, Tight), Next(random, Tight), Next(random, Tight), Next(random, Tight), Next(random, Tight)));
		}

		return values;
	}

	internal static string Show(in Field448 value)
	{
		return $"[{string.Join(", ", LimbsOf(value).Select(static limb => limb.ToString("X")))}]";
	}
}
