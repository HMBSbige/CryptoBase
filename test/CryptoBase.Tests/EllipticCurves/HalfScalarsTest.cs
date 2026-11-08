using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

public class HalfScalarsTest
{
	private const int RandomCount = 256;

	private static readonly BigInteger Half = BigInteger.One << 128;

	// HalfScalars splits u below n into v1 ≡ v2·u (mod n) with 0 ≤ v1 < 2^128 and 0 < |v2| < 2^128, for the orders of SM2 and P-256: the ends of the range; values around 2^128, the first remainder below which ends the steps, and 2^192; values that n divides by about 2^64 to 2^127 and values that n is near a multiple of, whose first quotients the leading bits of the remainders cannot take; and random values.
	[Test]
	public async Task SplitGivesHalfScalars()
	{
		await Assert.That(Check<SM2Order>()).IsEmpty();
		await Assert.That(Check<P256Order>()).IsEmpty();
	}

	private static List<string> Check<TOrder>() where TOrder : unmanaged, IMontgomeryModulus
	{
		BigInteger n = ModulusCase.FromLimbs(TOrder.Modulus);
		SortedSet<BigInteger> scalars = [0, 1, 2, 3, n - 1, n - 2, n - 3, (n - 1) / 2, (n + 1) / 2, Half - 1];

		for (int s = -2; s <= 2; ++s)
		{
			scalars.Add(Half + s);
			scalars.Add((BigInteger.One << 192) + s);
			scalars.Add(n - Half + s);

			foreach (int shift in (int[])[64, 65, 100, 126, 127])
			{
				scalars.Add((n >> shift) + s);
				scalars.Add((n >> shift) * 3 + s);
			}
		}

		Random random = new(31);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, n));
		}

		scalars.RemoveWhere(scalar => scalar < 0 || scalar >= n);
		List<string> failures = [];

		foreach (BigInteger scalar in scalars)
		{
			FieldElement<TOrder>.TryImport(CurveCase.EncodeInteger(scalar, TOrder.ByteLength), out FieldElement<TOrder> element);
			HalfScalars<TOrder>.Split(in element, out UInt128 first, out UInt128 second, out bool negative);
			BigInteger v1 = first;
			BigInteger v2 = negative ? -(BigInteger)second : second;

			if (second == 0 || BigInteger.Remainder(v1 - v2 * scalar, n) != 0)
			{
				failures.Add($"{scalar:X} gave {v1:X} and {v2:X}");
			}
		}

		return failures;
	}
}
