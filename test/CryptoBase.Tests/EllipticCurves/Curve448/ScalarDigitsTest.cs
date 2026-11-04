using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

// The signed comb digits sum to an odd value ≡ k (mod L), k itself when k is odd; the NAF digits sum to k.
public class ScalarDigitsTest
{
	[Test]
	public async Task SignedCombDigitsSumToTheScalar()
	{
		List<string> failures = [];

		foreach (BigInteger k in Scalars(new Random(1), 8))
		{
			ulong[] limbs = new ulong[ScalarDigits.LimbCount];
			ScalarDigits.ReadLimbs(Scalar(k), limbs);

			foreach (int digitCount in (int[])[450, 455, 512])
			{
				ulong[] digits = new ulong[ScalarDigits.CombLimbCount];
				ScalarDigits.SignedComb(limbs, digitCount, digits);
				BigInteger recoded = digits.Select(static (limb, i) => (BigInteger)limb << 64 * i).Aggregate(BigInteger.Add);
				BigInteger sum = 2 * recoded - ((BigInteger.One << digitCount) - 1);
				BigInteger expected = k.IsEven ? k + L : k;

				if (recoded >> digitCount != 0 || sum != expected)
				{
					failures.Add($"SignedComb {k:X}, {digitCount} digits");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task CombIndexReadsTheTeeth()
	{
		ulong[] limbs = [0x8000000000000001, 0, 0, 0, 0, 0, 0, 0x2];

		using (Assert.Multiple())
		{
			await Assert.That(ScalarDigits.CombIndex(limbs, 0, 63, 3)).IsEqualTo(3u);
			await Assert.That(ScalarDigits.CombIndex(limbs, 449, 1, 2)).IsEqualTo(1u);
			await Assert.That(ScalarDigits.CombIndex(limbs, 1, 5, 6)).IsEqualTo(0u);
		}
	}

	[Test]
	public async Task NonAdjacentFormsSumToTheScalar()
	{
		List<string> failures = [];

		foreach (BigInteger k in Scalars(new Random(2), 8))
		{
			ulong[] limbs = new ulong[ScalarDigits.LimbCount];
			ScalarDigits.ReadLimbs(Scalar(k), limbs);

			foreach (int width in (int[])[2, 5, 6, 8])
			{
				sbyte[] digits = new sbyte[449];
				int top = NonAdjacentForm.Recode(limbs, 0, 448, width, digits);
				BigInteger sum = digits.Select(static (digit, i) => (BigInteger)digit << i).Aggregate(BigInteger.Add);
				bool odd = digits.All(digit => digit is 0 || (digit & 1) is not 0 && Math.Abs((int)digit) < 1 << width - 1);

				if (sum != k || !odd || top != (k.IsZero ? -1 : Array.FindLastIndex(digits, static digit => digit is not 0)))
				{
					failures.Add($"NonAdjacentForm {k:X}, width {width}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
