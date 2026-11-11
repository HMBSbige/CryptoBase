using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// Each pair kernel against the single kernel of each modulus, bit for bit: the halves of a pair must come out as the contexts of the moduli compute them, for random values and the ends of [0, 2n), and so must exponentiations, which take moduli of up to MaxExponentiationLimbs.
public class MontgomeryPairTest
{
	[Test]
	public async Task EveryPairKernelIsListed()
	{
		await Assert.That(MontgomeryPairKernelCase.All().Select(static kernel => kernel.KernelType.GetGenericTypeDefinition()).Distinct()).IsEquivalentTo(ImplementationsOf(typeof(IMontgomeryPairKernel)));
	}

	// A pair where the platform has a pair kernel that holds the digits of both moduli, of one limb count, within the window or limb bounds that MontgomeryKernelDispatch sets for pairs; the smallest such window, or with AVX2 alone the window of every vector past vector 0 as far as MaxAvx2WindowVectors. The contexts of the moduli have the digits of the pair kernel, or are those of Create without a pair.
	[Test]
	public async Task DispatchPairsWhereItIsFaster()
	{
		List<string> failures = [];
		MontgomeryPairKernelCase[] kernels = [.. MontgomeryPairKernelCase.All().Where(static kernel => kernel.IsSupported)];
		bool avx2 = !MontgomeryKernelAvx512<Avx512Window>.IsSupported && MontgomeryPairKernelAvx2<Avx2PairWindow>.IsSupported;

		for (int limbs = 1; limbs <= 64; ++limbs)
		{
			ulong[] p = ToLimbs((BigInteger.One << 64 * limbs) - 1, limbs);
			ulong[] q = ToLimbs((BigInteger.One << 64 * limbs - 1) + 1, limbs);
			ulong[] longer = ToLimbs((BigInteger.One << 64 * limbs + 63) + 1, limbs + 1);
			using MontgomeryContext single = MontgomeryKernelDispatch.Create(p);
			using MontgomeryContext longerSingle = MontgomeryKernelDispatch.Create(longer);
			int vectors = (single.DigitCount + 3) / 4;
			bool expected = MontgomeryPairKernelAvx512<Avx512PairWindow>.IsSupported && vectors is >= MontgomeryKernelDispatch.MinAvx512PairVectors and <= MontgomeryKernelDispatch.MaxAvx512PairVectors || MontgomeryPairKernelAdvSimd<Radix28>.IsSupported && limbs is >= MontgomeryKernelDispatch.MinAdvSimdPairLimbs and <= MontgomeryKernelDispatch.MaxAdvSimdPairLimbs || avx2 && single.DigitCount >= MontgomeryPairKernelAvx2<Avx2PairWindow>.MinDigitCount;

			using (MontgomeryPairContext? pair = MontgomeryKernelDispatch.CreatePair(p, q, out MontgomeryContext first, out MontgomeryContext second))
			using (first)
			using (second)
			{
				MontgomeryPairKernelCase? chosen = pair is null ? null : kernels.Single(kernel => kernel.KernelType == pair.GetType().GetGenericArguments()[0]);
				bool otherWindow = chosen is not null && (chosen.KernelType.GetGenericTypeDefinition() == typeof(MontgomeryPairKernelAvx2<>) ? chosen.WindowVectors != Math.Min(Math.Max((first.DigitCount + 1) / 2, 2) - 1, MontgomeryKernelDispatch.MaxAvx2WindowVectors) : kernels.Any(kernel => kernel.MaxDigitCount >= first.DigitCount && kernel.MaxDigitCount < chosen.MaxDigitCount));

				if (pair is null == expected || chosen is not null && (chosen.MaxDigitCount < first.DigitCount || otherWindow))
				{
					failures.Add($"{limbs} limbs: {chosen?.ToString() ?? "no pair"}");
				}

				using MontgomeryContext expectedSingle = chosen?.CreateSingle(p) ?? MontgomeryKernelDispatch.Create(p);

				if (first.GetType() != expectedSingle.GetType() || second.GetType() != expectedSingle.GetType())
				{
					failures.Add($"{limbs} limbs: {first.GetType().Name} and {second.GetType().Name} with {chosen?.ToString() ?? "no pair"}");
				}
			}

			using (MontgomeryPairContext? unequal = MontgomeryKernelDispatch.CreatePair(p, longer, out MontgomeryContext first, out MontgomeryContext second))
			using (first)
			using (second)
			{
				if (unequal is not null || first.GetType() != single.GetType() || second.GetType() != longerSingle.GetType())
				{
					failures.Add($"{limbs} and {limbs + 1} limbs: {unequal?.GetType().Name ?? "no pair"} with {first.GetType().Name} and {second.GetType().Name}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task ProductsMatchTheSingleKernel(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(71);

		foreach ((MontgomeryContext first, BigInteger p, MontgomeryContext second, BigInteger q) in Pairs(kernel, random))
		{
			using (first)
			using (second)
			{
				int digits = first.DigitCount;
				ulong[] pDigits = new ulong[digits];
				ulong[] qDigits = new ulong[digits];
				first.ToDigits(first.Modulus, pDigits);
				second.ToDigits(second.Modulus, qDigits);
				BigInteger[] xs = Elements(random, p);
				BigInteger[] ys = Elements(random, q);

				// Every value of each with values of the other that differ, the ends of one with random values of the other among them.
				for (int i = 0; i < xs.Length; ++i)
				{
					for (int j = 0; j < 3; ++j)
					{
						BigInteger x = xs[i];
						BigInteger y = ys[(i + 3 * j + 1) % ys.Length];
						BigInteger u = xs[(i + 5 * j + 2) % xs.Length];
						BigInteger v = ys[(i + j) % ys.Length];
						Compare(failures, kernel, first, second, pDigits, qDigits, x, y, u, v, true, $"{p:X}, {q:X}: ({x:X}, {y:X})·({u:X}, {v:X})");
					}
				}

				// Any value of the digit count times a value below n, as ToMontgomery passes.
				BigInteger any = (BigInteger.One << kernel.DigitBits * digits) - 1;
				Compare(failures, kernel, first, second, pDigits, qDigits, any, any, RandomBelow(random, p), RandomBelow(random, q), false, $"{p:X}, {q:X}: R − 1 times values below n");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Chains of products and squares, each output feeding the next operation as in an exponentiation.
	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task ChainsMatchTheSingleKernel(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(72);

		foreach ((MontgomeryContext first, BigInteger p, MontgomeryContext second, BigInteger q) in Pairs(kernel, random))
		{
			using (first)
			using (second)
			{
				int digits = first.DigitCount;
				ulong[] pDigits = new ulong[digits];
				ulong[] qDigits = new ulong[digits];
				first.ToDigits(first.Modulus, pDigits);
				second.ToDigits(second.Modulus, qDigits);
				ulong[] x = ToLimbs(RandomBelow(random, 2 * p), digits, kernel.DigitBits);
				ulong[] y = ToLimbs(RandomBelow(random, 2 * q), digits, kernel.DigitBits);
				ulong[] u = ToLimbs(RandomBelow(random, 2 * p), digits, kernel.DigitBits);
				ulong[] v = ToLimbs(RandomBelow(random, 2 * q), digits, kernel.DigitBits);
				ulong[] pair = Interleave(x, y);
				ulong[] factor = Interleave(u, v);

				for (int step = 0; step < 64; ++step)
				{
					if (step % 3 is 0)
					{
						first.Multiply(x, x, u);
						second.Multiply(y, y, v);
						kernel.Multiply(pDigits, qDigits, pair, pair, factor);
					}
					else
					{
						first.Square(x, x);
						second.Square(y, y);
						kernel.Square(pDigits, qDigits, pair, pair);
					}
				}

				if (!pair.AsSpan().SequenceEqual(Interleave(x, y)))
				{
					failures.Add($"{p:X}, {q:X}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Exponents of one limb up to the length of the moduli, or past 32 limbs of one and four, the two of a pair different, and some at the ends: zero, one and all ones.
	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task ExponentiateMatchesTheSingleContexts(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(73);

		foreach ((MontgomeryContext first, BigInteger p, MontgomeryContext second, BigInteger q) in Pairs(kernel, random, MaxExponentiationLimbs))
		{
			using (first)
			using (second)
			using (MontgomeryPairContext pair = kernel.Create(first, second))
			{
				int limbs = first.LimbCount;
				int digits = first.DigitCount;

				foreach (int length in (limbs <= 32 ? [1, 2, limbs] : (int[])[1, 4]).Distinct())
				{
					BigInteger ones = (BigInteger.One << 64 * length) - 1;
					BigInteger[] exponents = [BigInteger.Zero, BigInteger.One, ones, RandomBits(random, 64 * length), RandomBits(random, 64 * length)];

					for (int i = 0; i < exponents.Length; ++i)
					{
						ulong[] x = ToLimbs(RandomBelow(random, 2 * p), digits, kernel.DigitBits);
						ulong[] y = ToLimbs(RandomBelow(random, 2 * q), digits, kernel.DigitBits);
						ulong[] e = ToLimbs(exponents[i], length);
						ulong[] f = ToLimbs(exponents[(i + 2) % exponents.Length], length);
						ulong[] expectedX = new ulong[digits];
						ulong[] expectedY = new ulong[digits];
						first.Exponentiate(x, e, expectedX);
						second.Exponentiate(y, f, expectedY);
						ulong[] resultX = new ulong[digits];
						ulong[] resultY = new ulong[digits];
						pair.Exponentiate(x, e, y, f, resultX, resultY);

						if (!resultX.AsSpan().SequenceEqual(expectedX) || !resultY.AsSpan().SequenceEqual(expectedY))
						{
							failures.Add($"{p:X}, {q:X}: exponents {exponents[i]:X} and {exponents[(i + 2) % exponents.Length]:X}");
						}

						// In place, as Apply exponentiates.
						pair.Exponentiate(x, e, y, f, x, y);

						if (!x.AsSpan().SequenceEqual(expectedX) || !y.AsSpan().SequenceEqual(expectedY))
						{
							failures.Add($"{p:X}, {q:X}: exponents {exponents[i]:X} and {exponents[(i + 2) % exponents.Length]:X} in place");
						}
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// A pair whose contexts take other moduli, which it then takes, exponentiates as a new pair of them would, bit for bit.
	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task ResetMatchesANewPair(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(74);

		foreach ((MontgomeryContext first, BigInteger p, MontgomeryContext second, BigInteger q) in Pairs(kernel, random, MaxExponentiationLimbs))
		{
			using (first)
			using (second)
			using (MontgomeryPairContext pair = kernel.Create(first, second))
			{
				int limbs = first.LimbCount;
				int digits = first.DigitCount;
				BigInteger nextP = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
				BigInteger nextQ = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
				ulong[] pLimbs = ToLimbs(nextP, limbs);
				ulong[] qLimbs = ToLimbs(nextQ, limbs);
				first.Reset(pLimbs);
				second.Reset(qLimbs);
				pair.Reset(first, second);
				using MontgomeryContext freshFirst = kernel.CreateSingle(pLimbs);
				using MontgomeryContext freshSecond = kernel.CreateSingle(qLimbs);
				using MontgomeryPairContext fresh = kernel.Create(freshFirst, freshSecond);
				ulong[] x = ToLimbs(RandomBelow(random, 2 * nextP), digits, kernel.DigitBits);
				ulong[] y = ToLimbs(RandomBelow(random, 2 * nextQ), digits, kernel.DigitBits);
				int length = Math.Min(limbs, 4);
				ulong[] e = ToLimbs(RandomBits(random, 64 * length), length);
				ulong[] f = ToLimbs(RandomBits(random, 64 * length), length);
				ulong[] resetX = new ulong[digits];
				ulong[] resetY = new ulong[digits];
				ulong[] freshX = new ulong[digits];
				ulong[] freshY = new ulong[digits];
				pair.Exponentiate(x, e, y, f, resetX, resetY);
				fresh.Exponentiate(x, e, y, f, freshX, freshY);

				if (!resetX.AsSpan().SequenceEqual(freshX) || !resetY.AsSpan().SequenceEqual(freshY))
				{
					failures.Add($"{p:X}, {q:X} to {nextP:X}, {nextQ:X}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Dispose erases what a pair context holds of its moduli, which may be secret primes: the data and −n⁻¹ mod 2^DigitBits of each.
	[Test]
	[MethodDataSource(typeof(MontgomeryPairKernelCase), nameof(MontgomeryPairKernelCase.All))]
	public async Task DisposeErasesWhatTheModuliGive(MontgomeryPairKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((MontgomeryContext first, _, MontgomeryContext second, _) in Pairs(kernel, new Random(73)))
		{
			using (first)
			using (second)
			{
				MontgomeryPairContext pair = kernel.Create(first, second);
				pair.Dispose();
				failures.AddRange(kernel.NonZeroWords(pair).Select(field => $"{first.LimbCount} limbs: {field}"));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Contexts of two moduli at the limb counts of MontgomeryPairKernelCase.LimbCountsToTest up to maxLimbs, in the shapes of ModuliToTest for each paired with a random one, both ways round.
	private static IEnumerable<(MontgomeryContext First, BigInteger P, MontgomeryContext Second, BigInteger Q)> Pairs(MontgomeryPairKernelCase kernel, Random random, int maxLimbs = int.MaxValue)
	{
		foreach (int limbs in kernel.LimbCountsToTest.Where(limbs => limbs <= maxLimbs))
		{
			int digits = kernel.GetDigitCount(limbs);
			int index = 0;

			foreach (BigInteger n in ModuliToTest(random, limbs))
			{
				BigInteger other = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
				(BigInteger p, BigInteger q) = (index++ & 1) is 0 ? (n, other) : (other, n);
				MontgomeryContext first = kernel.CreateSingle(ToLimbs(p, limbs));
				MontgomeryContext second = kernel.CreateSingle(ToLimbs(q, limbs));

				if (first.DigitCount != digits)
				{
					throw new InvalidOperationException($"The single kernel for {limbs} limbs has other digits than {kernel}.");
				}

				yield return (first, p, second, q);
			}
		}
	}

	// Values below 2n: the ends of [0, n) and [n, 2n) and random ones in both.
	private static BigInteger[] Elements(Random random, BigInteger n)
	{
		return [BigInteger.Zero, BigInteger.One, n - 1, n, n + 1, 2 * n - 1, RandomBelow(random, n), n + RandomBelow(random, n)];
	}

	// x·u and y·v, and with square, which needs x and y below 2n, their squares.
	private static void Compare(List<string> failures, MontgomeryPairKernelCase kernel, MontgomeryContext first, MontgomeryContext second, ulong[] pDigits, ulong[] qDigits, BigInteger x, BigInteger y, BigInteger u, BigInteger v, bool square, string description)
	{
		int digits = first.DigitCount;
		ulong[] xs = ToLimbs(x, digits, kernel.DigitBits);
		ulong[] ys = ToLimbs(y, digits, kernel.DigitBits);
		ulong[] us = ToLimbs(u, digits, kernel.DigitBits);
		ulong[] vs = ToLimbs(v, digits, kernel.DigitBits);
		ulong[] expectedX = new ulong[digits];
		ulong[] expectedY = new ulong[digits];
		first.Multiply(expectedX, xs, us);
		second.Multiply(expectedY, ys, vs);
		ulong[] product = new ulong[2 * digits];
		kernel.Multiply(pDigits, qDigits, product, Interleave(xs, ys), Interleave(us, vs));

		if (!product.AsSpan().SequenceEqual(Interleave(expectedX, expectedY)))
		{
			failures.Add(description);
		}

		if (!square)
		{
			return;
		}

		first.Square(expectedX, xs);
		second.Square(expectedY, ys);
		ulong[] squares = Interleave(xs, ys);
		kernel.Square(pDigits, qDigits, squares, squares);

		if (!squares.AsSpan().SequenceEqual(Interleave(expectedX, expectedY)))
		{
			failures.Add($"{description}, squares of the left");
		}
	}

	private static ulong[] Interleave(ulong[] first, ulong[] second)
	{
		ulong[] pair = new ulong[2 * first.Length];

		for (int i = 0; i < first.Length; ++i)
		{
			pair[2 * i] = first[i];
			pair[2 * i + 1] = second[i];
		}

		return pair;
	}
}
