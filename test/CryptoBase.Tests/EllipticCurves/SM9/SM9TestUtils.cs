using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;

namespace CryptoBase.Tests.EllipticCurves.SM9;

internal static class SM9TestUtils
{
	private const ulong LimbMask = (1UL << 52) - 1;

	// Reduced elements are below 2.25p.
	internal static readonly BigInteger ReducedBound = 9 * P / 4;

	private static readonly BigInteger MontgomeryRInverse = Inverse(MontgomeryR);

	// The element with the limbs of value in radix 2^52, limb 4 taking all the bits from 208 on.
	internal static SM9Fp Raw(BigInteger value)
	{
		return new SM9Fp
		{
			L0 = (ulong)(value & LimbMask),
			L1 = (ulong)(value >> 52 & LimbMask),
			L2 = (ulong)(value >> 104 & LimbMask),
			L3 = (ulong)(value >> 156 & LimbMask),
			L4 = (ulong)(value >> 208),
		};
	}

	internal static SM9Fp Limbs(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
	{
		return new SM9Fp { L0 = l0, L1 = l1, L2 = l2, L3 = l3, L4 = l4 };
	}

	internal static ulong[] LimbsOf(in SM9Fp value)
	{
		return [value.L0, value.L1, value.L2, value.L3, value.L4];
	}

	internal static BigInteger RawValue(in SM9Fp value)
	{
		return LimbsOf(value).Select((limb, i) => (BigInteger)limb << 52 * i).Aggregate(BigInteger.Add);
	}

	// The Montgomery form of a plain value, canonical.
	private static SM9Fp Element(BigInteger plain)
	{
		return Raw(Mod(Mod(plain) * MontgomeryR));
	}

	// The plain value of an element in Montgomery form.
	internal static BigInteger ValueOf(in SM9Fp value)
	{
		return Mod(RawValue(value) * MontgomeryRInverse);
	}

	internal static bool IsReduced(in SM9Fp value)
	{
		return value is { L0: <= LimbMask, L1: <= LimbMask, L2: <= LimbMask, L3: <= LimbMask } && RawValue(value) < ReducedBound;
	}

	internal static SM9Fp2 Element(Fp2Value value)
	{
		return new SM9Fp2 { A0 = Element(value.A0), A1 = Element(value.A1) };
	}

	internal static Fp2Value ValueOf(in SM9Fp2 value)
	{
		return new Fp2Value(ValueOf(value.A0), ValueOf(value.A1));
	}

	internal static bool IsReduced(in SM9Fp2 value)
	{
		return IsReduced(value.A0) && IsReduced(value.A1);
	}

	// The coefficients of w⁰ to w⁵ are C0.C0, C1.C0, C0.C1, C1.C1, C0.C2 and C1.C2.
	internal static SM9Fp12 Element(Fp12Value value)
	{
		SM9Fp12 result = default;
		result.C0.C0 = Element(value.C[0]);
		result.C1.C0 = Element(value.C[1]);
		result.C0.C1 = Element(value.C[2]);
		result.C1.C1 = Element(value.C[3]);
		result.C0.C2 = Element(value.C[4]);
		result.C1.C2 = Element(value.C[5]);
		return result;
	}

	internal static Fp12Value ValueOf(in SM9Fp12 value)
	{
		return new Fp12Value([ValueOf(value.C0.C0), ValueOf(value.C1.C0), ValueOf(value.C0.C1), ValueOf(value.C1.C1), ValueOf(value.C0.C2), ValueOf(value.C1.C2)]);
	}

	internal static bool IsReduced(in SM9Fp12 value)
	{
		return IsReduced(value.C0.C0) && IsReduced(value.C0.C1) && IsReduced(value.C0.C2) && IsReduced(value.C1.C0) && IsReduced(value.C1.C1) && IsReduced(value.C1.C2);
	}

	internal static SM9AffinePoint<SM9Fp> Element(G1Value point)
	{
		return new SM9AffinePoint<SM9Fp> { X = Element(point.X), Y = Element(point.Y) };
	}

	internal static SM9AffinePoint<SM9Fp2> Element(G2Value point)
	{
		return new SM9AffinePoint<SM9Fp2> { X = Element(point.X), Y = Element(point.Y) };
	}

	// The projective form (xz : yz : z), or (0 : z : 0) for the point at infinity.
	internal static SM9Point<SM9Fp> Projective(G1Value? point, BigInteger z)
	{
		return point is null
			? new SM9Point<SM9Fp> { X = Element(0), Y = Element(z), Z = Element(0) }
			: new SM9Point<SM9Fp> { X = Element(point.X * z), Y = Element(point.Y * z), Z = Element(z) };
	}

	internal static SM9Point<SM9Fp2> Projective(G2Value? point, Fp2Value z)
	{
		return point is null
			? new SM9Point<SM9Fp2> { X = Element(Fp2Value.Zero), Y = Element(z), Z = Element(Fp2Value.Zero) }
			: new SM9Point<SM9Fp2> { X = Element(point.X * z), Y = Element(point.Y * z), Z = Element(z) };
	}

	internal static G1Value ValueOf(in SM9AffinePoint<SM9Fp> point)
	{
		return new G1Value(ValueOf(point.X), ValueOf(point.Y));
	}

	internal static G2Value ValueOf(in SM9AffinePoint<SM9Fp2> point)
	{
		return new G2Value(ValueOf(point.X), ValueOf(point.Y));
	}

	// Null for the point at infinity; throws for (0 : 0 : 0).
	internal static G1Value? ValueOf(in SM9Point<SM9Fp> point)
	{
		BigInteger z = ValueOf(point.Z);

		if (z.IsZero)
		{
			return ValueOf(point.X).IsZero && !ValueOf(point.Y).IsZero ? null : throw new InvalidOperationException("Not a point.");
		}

		BigInteger inverse = Inverse(z);
		return new G1Value(Mod(ValueOf(point.X) * inverse), Mod(ValueOf(point.Y) * inverse));
	}

	internal static G2Value? ValueOf(in SM9Point<SM9Fp2> point)
	{
		Fp2Value z = ValueOf(point.Z);

		if (z.IsZero)
		{
			return ValueOf(point.X).IsZero && !ValueOf(point.Y).IsZero ? null : throw new InvalidOperationException("Not a point.");
		}

		Fp2Value inverse = z.Inverse();
		return new G2Value(ValueOf(point.X) * inverse, ValueOf(point.Y) * inverse);
	}

	internal static FieldElement<SM9Order> Scalar(BigInteger value)
	{
		FieldElement<SM9Order>.ImportReduced(Encode(ModN(value)), out FieldElement<SM9Order> scalar);
		return scalar;
	}

	internal static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		byte[] bytes = new byte[(int)(bound.GetBitLength() + 7) / 8 + 8];
		random.NextBytes(bytes);
		return new BigInteger(bytes, isUnsigned: true) % bound;
	}

	internal static Fp2Value RandomFp2(Random random)
	{
		return new Fp2Value(RandomBelow(random, P), RandomBelow(random, P));
	}

	internal static Fp12Value RandomFp12(Random random)
	{
		return new Fp12Value(Enumerable.Range(0, 6).Select(_ => RandomFp2(random)).ToArray());
	}

	// Reduced elements of extreme limbs and values: 0, p and 2p and their neighbours, 2^256 − 1, the largest value below 2.25p with limbs 0 to 3 all ones, and the largest reduced value.
	internal static List<SM9Fp> EdgeElements()
	{
		BigInteger largest = ReducedBound - 1;
		return [Raw(0), Raw(1), Raw(P - 1), Raw(P), Raw(P + 1), Raw(2 * P - 1), Raw(2 * P), Raw(2 * P + 1), Raw((BigInteger.One << 256) - 1), Raw((largest >> 208 << 208) - 1), Raw(largest)];
	}

	// Edge elements and random reduced ones, raw values below 2.25p.
	internal static List<SM9Fp> ReducedElements(Random random, int count)
	{
		List<SM9Fp> values = EdgeElements();

		for (int i = 0; i < count; ++i)
		{
			values.Add(Raw(RandomBelow(random, ReducedBound)));
		}

		return values;
	}

	internal static string Show(in SM9Fp value)
	{
		return $"[{string.Join(", ", LimbsOf(value).Select(static limb => limb.ToString("X")))}]";
	}
}
