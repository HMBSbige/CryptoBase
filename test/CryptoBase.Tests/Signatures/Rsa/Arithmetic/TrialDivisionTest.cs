using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// TrialDivision against BigInteger, at candidate lengths up to the 8192 bits of the primes of RSA-16384, whose sums of products are the largest.
public class TrialDivisionTest
{
	private static readonly int[] Primes = [.. Enumerable.Range(3, TrialDivision.Bound - 3).Where(static n => (n & 1) is 1 && IsPrime(n))];

	public static IEnumerable<int> Lengths()
	{
		yield return 1;
		yield return 2;
		yield return 16;
		yield return 24;
		yield return 32;
		yield return 128;
	}

	[Test]
	[MethodDataSource(nameof(Lengths))]
	public async Task FindsEveryOddPrimeBelowBound(int limbs)
	{
		List<int> missed = [];
		Random random = new(limbs);
		TrialDivision trial = new(limbs);

		foreach (int prime in Primes)
		{
			// prime·k of limbs limbs, odd, with every half nonzero but those past the value.
			BigInteger k = RandomBits(random, 64 * limbs - 14) | BigInteger.One;

			if (!trial.HasSmallFactor(ToLimbs(prime * k, limbs)))
			{
				missed.Add(prime);
			}
		}

		await Assert.That(missed).IsEmpty();
	}

	[Test]
	[MethodDataSource(nameof(Lengths))]
	public async Task MatchesReference(int limbs)
	{
		List<string> failures = [];
		Random random = new(100 + limbs);
		TrialDivision trial = new(limbs);
		BigInteger largest = (BigInteger.One << 64 * limbs) - 1;
		BigInteger[] candidates = [largest, largest - 2, BigInteger.One, .. Enumerable.Range(0, 200).Select(_ => RandomBits(random, 64 * limbs) | BigInteger.One), .. Enumerable.Range(0, 20).Select(_ => Product(random, limbs))];

		foreach (BigInteger candidate in candidates)
		{
			bool expected = Primes.Any(prime => (candidate % prime).IsZero);

			if (trial.HasSmallFactor(ToLimbs(candidate, limbs)) != expected)
			{
				failures.Add($"{candidate:X}: expected {expected}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Instances of lengths in turn, whose weights serve shorter candidates once taken for longer ones and are taken afresh for longer ones, match BigInteger.
	[Test]
	public async Task LengthsInTurnMatchReference()
	{
		List<string> failures = [];
		Random random = new(300);

		foreach (int limbs in (int[])[128, 1, 16, 32, 2, 24, 128])
		{
			TrialDivision trial = new(limbs);
			BigInteger[] candidates = [.. Enumerable.Range(0, 40).Select(_ => RandomBits(random, 64 * limbs) | BigInteger.One), .. Primes.Where((_, i) => i % 64 is 0).Select(prime => prime * (RandomBits(random, 64 * limbs - 14) | BigInteger.One))];

			foreach (BigInteger candidate in candidates)
			{
				bool expected = Primes.Any(prime => (candidate % prime).IsZero);

				if (trial.HasSmallFactor(ToLimbs(candidate, limbs)) != expected)
				{
					failures.Add($"{limbs} limbs, {candidate:X}: expected {expected}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A product of primes above the bound that fits limbs limbs, which no small prime divides.
	private static BigInteger Product(Random random, int limbs)
	{
		BigInteger product = BigInteger.One;

		while (true)
		{
			BigInteger factor = RandomPrime(random, 20);
			BigInteger next = product * factor;

			if (next.GetBitLength() > 64 * limbs)
			{
				return product;
			}

			product = next;
		}
	}

	private static bool IsPrime(int n)
	{
		for (int d = 3; d * d <= n; d += 2)
		{
			if (n % d is 0)
			{
				return false;
			}
		}

		return n > 2;
	}
}
