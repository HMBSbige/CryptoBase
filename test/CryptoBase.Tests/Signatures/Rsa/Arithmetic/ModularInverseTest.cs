using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

public class ModularInverseTest
{
	// The inputs that need the most divsteps are out of reach of the inversion tests, so the batches must cover the bound by construction.
	[Test]
	public async Task BatchesCoverTheStepBound()
	{
		List<string> failures = [];

		for (int limbs = 1; limbs <= 256; ++limbs)
		{
			int stepBound = ModularInverse.GetSchedule(limbs, out int batchCount, out int batchSteps);

			if (stepBound != (45907L * 64 * limbs + 26313) / 19929 || batchSteps > 62 || batchCount * batchSteps < stepBound)
			{
				failures.Add($"{limbs} limbs: {batchCount} × {batchSteps} for {stepBound}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task InverseMatchesReference()
	{
		List<string> failures = [];
		Random random = new(31);

		foreach (int limbs in LimbCounts)
		{
			foreach (BigInteger m in Moduli(random, limbs))
			{
				foreach (BigInteger value in (ReadOnlySpan<BigInteger>)[BigInteger.One, m - 1, 2, RandomBelow(random, m)])
				{
					if (!BigInteger.GreatestCommonDivisor(value, m).IsOne)
					{
						continue;
					}

					foreach (BigInteger numerator in (ReadOnlySpan<BigInteger>)[BigInteger.One, m - 1, RandomBelow(random, m)])
					{
						BigInteger expected = numerator * ModInverse(value, m) % m;
						ulong[] result = new ulong[limbs];
						ModularInverse.Invert(ToLimbs(value, limbs), ToLimbs(numerator, limbs), ToLimbs(m, limbs), result);

						if (ToBigInteger(result) != expected)
						{
							failures.Add($"{numerator:X}/{value:X} mod {m:X}");
						}

						// The result may be the numerator, as unblinding uses it.
						ulong[] shared = ToLimbs(numerator, limbs);
						ModularInverse.Invert(ToLimbs(value, limbs), shared, ToLimbs(m, limbs), shared);

						if (ToBigInteger(shared) != expected)
						{
							failures.Add($"{numerator:X}/{value:X} mod {m:X} in place");
						}
					}
				}

				ulong[] zero = new ulong[limbs];
				ModularInverse.Invert(new ulong[limbs], ToLimbs(BigInteger.One, limbs), ToLimbs(m, limbs), zero);

				if (!ToBigInteger(zero).IsZero)
				{
					failures.Add($"1/0 mod {m:X}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
