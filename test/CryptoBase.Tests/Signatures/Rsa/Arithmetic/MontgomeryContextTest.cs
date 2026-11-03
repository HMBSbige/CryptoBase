using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Numerics;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// Checks every kernel, through MontgomeryContext, against BigInteger. Elements below 2n pass if they are congruent to the reference and every digit is below the radix, as IMontgomeryKernel allows.
// Each kernel is checked at the limb counts of MontgomeryKernelCase.LimbCountsToTest with the moduli of ModuliToTest, and exponentiations up to MaxExponentiationLimbs; EveryOperationMatchesAtEveryLimbCount checks every limb count of LimbCounts that the kernel holds with every modulus of Moduli, on request.
public class MontgomeryContextTest
{
	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(MontgomeryKernelCase.All().Select(static kernel => kernel.KernelType.GetGenericTypeDefinition()).Distinct()).IsEquivalentTo(ImplementationsOf(typeof(IMontgomeryKernel)));
	}

	// The dispatch takes a vector kernel where the platform has one whose windows hold the digits, with the smallest window that does, and otherwise the largest digits that fit in the family of kernels for the platform, so that a modulus of any size up to 16384 bits gets a kernel. With AVX-512, the windows of eight vectors or more keep the operands in staging. With AVX2, MontgomeryKernelAvx2 takes every modulus that AVX-512 does not, with every vector of four digits past vector 0 in its window as far as MaxAvx2WindowVectors.
	// On ARM64 the family is MontgomeryKernel64ColumnPairs for the shorter moduli and MontgomeryKernelAdvSimd for the longer ones.
	[Test]
	public async Task DispatchTakesTheBestKernelThatFits()
	{
		List<string> failures = [];
		MontgomeryKernelCase[] kernels = [.. MontgomeryKernelCase.All().Where(static kernel => kernel.IsSupported)];
		bool arm64 = MontgomeryKernelAdvSimd<Radix28>.IsSupported;
		Type platformFamily = MontgomeryKernel64<Radix57>.IsSupported ? typeof(MontgomeryKernel64<>) : typeof(MontgomeryKernel32<>);
		bool advSimd = false;

		foreach (int limbs in Enumerable.Range(1, 256))
		{
			ulong[] modulus = ToLimbs((BigInteger.One << 64 * limbs) - 1, limbs);
			using MontgomeryContext context = MontgomeryKernelDispatch.Create(modulus);
			Type kernelType = context.GetType().GetGenericArguments()[0];
			MontgomeryKernelCase chosen = kernels.Single(kernel => kernel.KernelType == kernelType);
			Type family = chosen.KernelType.GetGenericTypeDefinition();
			MontgomeryKernelCase[] fitting = [.. kernels.Where(kernel => kernel.KernelType.GetGenericTypeDefinition() == family && kernel.Fits(limbs))];
			bool vector = MontgomeryKernelCase.IsVector(chosen.KernelType);
			bool expectedFamily;

			if (arm64)
			{
				// Once the AdvSimd kernel is chosen, every longer modulus keeps it.
				expectedFamily = family == typeof(MontgomeryKernelAdvSimd<>) || family == typeof(MontgomeryKernel64ColumnPairs<>) && !advSimd;
				advSimd |= family == typeof(MontgomeryKernelAdvSimd<>);
			}
			else
			{
				int avx512Vectors = (MontgomeryContext<MontgomeryKernelAvx512<Avx512Window>>.GetDigitCount(limbs) + 7) / 8;
				bool avx512 = MontgomeryKernelAvx512<Avx512Window>.IsSupported && avx512Vectors <= MontgomeryKernelDispatch.MaxAvx512Vectors;
				Type avx512Family = avx512Vectors < MontgomeryKernelDispatch.MinAvx512StagedVectors ? typeof(MontgomeryKernelAvx512<>) : typeof(MontgomeryKernelAvx512Staged<>);
				Type expected = avx512 ? avx512Family : MontgomeryKernelAvx2<Avx2Window>.IsSupported ? typeof(MontgomeryKernelAvx2<>) : platformFamily;
				expectedFamily = family == expected;
			}

			int vectors = Math.Max((context.DigitCount + 3) / 4, 2);
			bool better = family == typeof(MontgomeryKernelAvx2<>) ? MontgomeryKernelCase.WindowVectors(chosen.KernelType) != Math.Min(vectors - 1, MontgomeryKernelDispatch.MaxAvx2WindowVectors) : vector ? fitting.Any(kernel => kernel.MaxDigitCount < chosen.MaxDigitCount) : fitting.Any(kernel => kernel.DigitBits > chosen.DigitBits);

			if (!chosen.Fits(limbs) || !expectedFamily || better)
			{
				failures.Add($"{limbs} limbs: {chosen}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ChainsMatchTheScalarKernel(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Chains(kernel, false)).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task MultiplyMatchesReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Multiply(kernel, false)).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task SquareMatchesReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Square(kernel, false)).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ConversionsMatchReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Conversions(kernel, false)).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task SubtractMatchesReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Subtract(kernel, false)).IsEmpty();
	}

	// MontgomeryContext exponentiates alike with every kernel, so ExponentiateThroughTheDispatchMatchesReference takes every way to exponentiate; here each kernel takes a random exponent of a few windows per modulus, into another element and in place.
	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ExponentiateMatchesReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Exponentiate(kernel, false)).IsEmpty();
	}

	// Every way to exponentiate of Exponentiate, through the kernel that MontgomeryKernelDispatch takes for the limb count.
	[Test]
	[MethodDataSource(nameof(ExponentiationLimbCounts))]
	public async Task ExponentiateThroughTheDispatchMatchesReference(int limbs)
	{
		List<string> failures = [];
		Random random = new(limbs);

		foreach (BigInteger n in ModuliToTest(random, limbs))
		{
			using MontgomeryContext context = MontgomeryKernelDispatch.Create(ToLimbs(n, limbs));
			ExponentiateEveryWay(failures, MontgomeryKernelCase.Of(context), context, n, random);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ExponentiateVariableTimeMatchesReference(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(ExponentiateVariableTime(kernel, false)).IsEmpty();
	}

	// A context that takes another modulus works as a new one of it would, bit for bit, through moduli of every shape and back to the first. Reset exponentiates to find R², so moduli stay within MaxExponentiationLimbs.
	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task ResetMatchesANewContext(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Reset(kernel, false)).IsEmpty();
	}

	// The checks above at every limb count of LimbCounts that the kernel holds, with every modulus of Moduli and every way to exponentiate: minutes for all kernels.
	[Test]
	[Explicit]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task EveryOperationMatchesAtEveryLimbCount(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);
		await Assert.That(Chains(kernel, true).Concat(Multiply(kernel, true)).Concat(Square(kernel, true)).Concat(Conversions(kernel, true)).Concat(Subtract(kernel, true)).Concat(Exponentiate(kernel, true)).Concat(ExponentiateVariableTime(kernel, true)).Concat(Reset(kernel, true))).IsEmpty();
	}

	// Dispose erases what a context holds of its modulus, which may be a secret prime: the data and −n⁻¹ mod 2^DigitBits, whose bits are those of the low bits of the modulus.
	[Test]
	[MethodDataSource(typeof(MontgomeryKernelCase), nameof(MontgomeryKernelCase.All))]
	public async Task DisposeErasesWhatTheModulusGives(MontgomeryKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Random random = new(9);

		foreach (int limbs in LimbCounts.Where(kernel.Fits).Take(3))
		{
			MontgomeryContext context = kernel.Create(ToLimbs(RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1, limbs));
			context.Dispose();
			failures.AddRange(NonZeroWords(context).Select(field => $"{limbs} limbs: {field}"));
		}

		await Assert.That(failures).IsEmpty();
	}

	// Limb counts around powers of two up to MaxExponentiationLimbs.
	public static IEnumerable<int> ExponentiationLimbCounts()
	{
		return [1, 2, 3, 5, 8, 9, 16, 17, 32, 33, 64];
	}

	// Chains of products and squares of random values, through the kernel and through the scalar kernel of the platform, give the same values as BigInteger: the representations differ, so the chains meet in plain form.
	private static List<string> Chains(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(7);

		foreach (int limbs in LimbCountsOf(kernel, full))
		{
			BigInteger n = RandomBits(random, 64 * limbs) | BigInteger.One << 64 * limbs - 1 | 1;
			ulong[] modulus = ToLimbs(n, limbs);
			using MontgomeryContext context = kernel.Create(modulus);
			using MontgomeryContext scalar = MontgomeryKernel64<Radix54>.IsSupported ? new MontgomeryContext<MontgomeryKernel64<Radix54>>(modulus) : new MontgomeryContext<MontgomeryKernel32<Radix27>>(modulus);
			BigInteger expected = RandomBelow(random, n);
			ulong[] value = new ulong[context.DigitCount];
			ulong[] scalarValue = new ulong[scalar.DigitCount];
			ulong[] factor = new ulong[context.DigitCount];
			ulong[] scalarFactor = new ulong[scalar.DigitCount];
			ulong[] result = new ulong[limbs];
			ulong[] scalarResult = new ulong[limbs];
			context.ToMontgomery(ToLimbs(expected, limbs), value);
			scalar.ToMontgomery(ToLimbs(expected, limbs), scalarValue);

			for (int step = 0; step < 24; ++step)
			{
				if (step % 3 is 2)
				{
					context.Square(value, value);
					scalar.Square(scalarValue, scalarValue);
					expected = expected * expected % n;
					continue;
				}

				BigInteger y = RandomBelow(random, n);
				context.ToMontgomery(ToLimbs(y, limbs), factor);
				scalar.ToMontgomery(ToLimbs(y, limbs), scalarFactor);
				context.Multiply(value, value, factor);
				scalar.Multiply(scalarValue, scalarValue, scalarFactor);
				expected = expected * y % n;
			}

			context.FromMontgomery(value, result);
			scalar.FromMontgomery(scalarValue, scalarResult);

			if (!result.AsSpan().SequenceEqual(scalarResult) || ToBigInteger(result) != expected)
			{
				failures.Add($"{limbs} limbs, {n:X}: {ToBigInteger(result):X}, the scalar kernel {ToBigInteger(scalarResult):X}, expected {expected:X}");
			}
		}

		return failures;
	}

	private static List<string> Multiply(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full))
		{
			using (context)
			{
				BigInteger r = BigInteger.One << kernel.DigitBits * context.DigitCount;
				BigInteger rInverse = ModInverse(r % n, n);
				BigInteger[] values = Elements(random, n, full);

				foreach (BigInteger a in values)
				{
					foreach (BigInteger b in values.Take(4).Append(RandomBelow(random, 2 * n)))
					{
						BigInteger expected = a * b * rInverse % n;
						ulong[] left = ToLimbs(a, context.DigitCount, kernel.DigitBits);
						ulong[] right = ToLimbs(b, context.DigitCount, kernel.DigitBits);
						ulong[] result = new ulong[context.DigitCount];
						context.Multiply(result, left, right);
						Check(failures, kernel, result, expected, n, $"{n:X}: {a:X}·{b:X}");
						context.Multiply(left, left, right);
						Check(failures, kernel, left, expected, n, $"{n:X}: {a:X}·{b:X} into left");
						left = ToLimbs(a, context.DigitCount, kernel.DigitBits);
						context.Multiply(right, left, right);
						Check(failures, kernel, right, expected, n, $"{n:X}: {a:X}·{b:X} into right");
					}
				}

				// Any value of the digit count times a value below n, as ToMontgomery passes.
				BigInteger any = (BigInteger.One << kernel.DigitBits * context.DigitCount) - 1;
				BigInteger below = RandomBelow(random, n);
				ulong[] anyResult = new ulong[context.DigitCount];
				context.Multiply(anyResult, ToLimbs(any, context.DigitCount, kernel.DigitBits), ToLimbs(below, context.DigitCount, kernel.DigitBits));
				Check(failures, kernel, anyResult, any * below * rInverse % n, n, $"{n:X}: R − 1 times {below:X}");
			}
		}

		return failures;
	}

	private static List<string> Square(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(2);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full))
		{
			using (context)
			{
				BigInteger r = BigInteger.One << kernel.DigitBits * context.DigitCount;
				BigInteger rInverse = ModInverse(r % n, n);

				foreach (BigInteger a in Elements(random, n, full))
				{
					BigInteger expected = a * a * rInverse % n;
					ulong[] value = ToLimbs(a, context.DigitCount, kernel.DigitBits);
					ulong[] result = new ulong[context.DigitCount];
					context.Square(result, value);
					Check(failures, kernel, result, expected, n, $"{n:X}: {a:X}²");
					context.Square(value, value);
					Check(failures, kernel, value, expected, n, $"{n:X}: {a:X}² in place");
				}
			}
		}

		return failures;
	}

	private static List<string> Conversions(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(3);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full))
		{
			using (context)
			{
				int limbs = context.LimbCount;
				int digits = context.DigitCount;
				BigInteger r = BigInteger.One << kernel.DigitBits * digits;
				ulong[] element = new ulong[digits];
				ulong[] result = new ulong[limbs];

				// Values shorter and longer than the modulus, as the CRT reduces the input of the full modulus by each prime.
				foreach (int length in (ReadOnlySpan<int>)[1, limbs, limbs + 1, 2 * limbs, 3 * limbs + 1])
				{
					foreach (BigInteger value in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, BigInteger.One, (BigInteger.One << 64 * length) - 1, RandomBits(random, 64 * length)])
					{
						context.ToMontgomery(ToLimbs(value, length), element);
						Check(failures, kernel, element, value * r % n, n, $"{n:X}: ToMontgomery({value:X})");
						context.FromMontgomery(element, result);

						if (ToBigInteger(result) != value % n)
						{
							failures.Add($"{n:X}: FromMontgomery(ToMontgomery({value:X}))");
						}
					}
				}

				foreach (BigInteger value in Elements(random, n, full))
				{
					ulong[] digitsOfValue = ToLimbs(value, digits, kernel.DigitBits);
					context.FromDigits(digitsOfValue, result);

					if (ToBigInteger(result) != value % n)
					{
						failures.Add($"{n:X}: FromDigits({value:X})");
					}

					if (value < n)
					{
						context.ToDigits(ToLimbs(value, limbs), element);

						if (!element.AsSpan().SequenceEqual(digitsOfValue))
						{
							failures.Add($"{n:X}: ToDigits({value:X})");
						}
					}

					context.Reduce(digitsOfValue);

					if (ToBigInteger(digitsOfValue, kernel.DigitBits) != value % n)
					{
						failures.Add($"{n:X}: Reduce({value:X})");
					}
				}

				context.WriteOne(element);

				if (ToBigInteger(element, kernel.DigitBits) != r % n)
				{
					failures.Add($"{n:X}: One");
				}

				context.WriteRSquared(result);

				if (ToBigInteger(result) != r * r % n)
				{
					failures.Add($"{n:X}: R²");
				}

				if (!context.Modulus.SequenceEqual(ToLimbs(n, limbs)))
				{
					failures.Add($"{n:X}: Modulus");
				}
			}
		}

		return failures;
	}

	private static List<string> Subtract(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(4);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full))
		{
			using (context)
			{
				BigInteger[] values = Elements(random, n, full);

				foreach (BigInteger a in values)
				{
					foreach (BigInteger b in values)
					{
						ulong[] left = ToLimbs(a, context.DigitCount, kernel.DigitBits);
						ulong[] right = ToLimbs(b, context.DigitCount, kernel.DigitBits);
						context.Subtract(left, left, right);
						Check(failures, kernel, left, ((a - b) % n + n) % n, n, $"{n:X}: {a:X} − {b:X}");
					}
				}
			}
		}

		return failures;
	}

	private static List<string> Exponentiate(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(5);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full, MaxExponentiationLimbs))
		{
			using (context)
			{
				if (full)
				{
					ExponentiateEveryWay(failures, kernel, context, n, random);
				}
				else
				{
					int length = Math.Min(context.LimbCount, 2);
					ExponentiateAndCheck(failures, kernel, context, n, RandomBelow(random, 2 * n), RandomBits(random, 64 * length), length);
				}
			}
		}

		return failures;
	}

	// Exponents of one limb up to the length of the modulus cover every window size and a first window of every width.
	private static void ExponentiateEveryWay(List<string> failures, MontgomeryKernelCase kernel, MontgomeryContext context, BigInteger n, Random random)
	{
		int limbs = context.LimbCount;
		int[] lengths = limbs <= 32 ? [1, 2, (limbs + 1) / 2, limbs] : [1, 4];

		foreach (int length in lengths.Distinct())
		{
			BigInteger a = RandomBelow(random, 2 * n);

			foreach (BigInteger exponent in (ReadOnlySpan<BigInteger>)[BigInteger.Zero, BigInteger.One, 2, (BigInteger.One << 64 * length) - 1, RandomBits(random, 64 * length)])
			{
				ExponentiateAndCheck(failures, kernel, context, n, a, exponent, length);
			}
		}
	}

	// a^exponent, with the exponent in length limbs, into another element and in place.
	private static void ExponentiateAndCheck(List<string> failures, MontgomeryKernelCase kernel, MontgomeryContext context, BigInteger n, BigInteger a, BigInteger exponent, int length)
	{
		BigInteger r = BigInteger.One << kernel.DigitBits * context.DigitCount;
		BigInteger rInverse = ModInverse(r % n, n);
		ulong[] element = ToLimbs(a, context.DigitCount, kernel.DigitBits);
		ulong[] result = new ulong[context.DigitCount];
		BigInteger expected = BigInteger.ModPow(a * rInverse % n, exponent, n) * r % n;
		context.Exponentiate(element, ToLimbs(exponent, length), result);
		Check(failures, kernel, result, expected, n, $"{n:X}: {a:X}^{exponent:X}");
		context.Exponentiate(element, ToLimbs(exponent, length), element);
		Check(failures, kernel, element, expected, n, $"{n:X}: {a:X}^{exponent:X} in place");
	}

	private static List<string> ExponentiateVariableTime(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(6);

		foreach ((MontgomeryContext context, BigInteger n) in Contexts(kernel, random, full, MaxExponentiationLimbs))
		{
			using (context)
			{
				BigInteger r = BigInteger.One << kernel.DigitBits * context.DigitCount;
				BigInteger rInverse = ModInverse(r % n, n);
				BigInteger a = RandomBelow(random, 2 * n);

				foreach (ulong exponent in (ReadOnlySpan<ulong>)[0, 1, 2, 3, 65537, (1UL << 33) - 1, ulong.MaxValue, (ulong)random.NextInt64()])
				{
					ulong[] element = ToLimbs(a, context.DigitCount, kernel.DigitBits);
					BigInteger expected = BigInteger.ModPow(a * rInverse % n, exponent, n) * r % n;
					context.ExponentiateVariableTime(element, exponent, element);
					Check(failures, kernel, element, expected, n, $"{n:X}: {a:X}^{exponent:X}");
				}
			}
		}

		return failures;
	}

	private static List<string> Reset(MontgomeryKernelCase kernel, bool full)
	{
		List<string> failures = [];
		Random random = new(8);

		foreach (int limbs in LimbCountsOf(kernel, full).Where(limbs => full || limbs <= MaxExponentiationLimbs))
		{
			BigInteger[] moduli = [.. Moduli(random, limbs)];
			using MontgomeryContext context = kernel.Create(ToLimbs(moduli[0], limbs));

			foreach (BigInteger n in moduli.Skip(1).Append(moduli[0]))
			{
				ulong[] modulus = ToLimbs(n, limbs);
				context.Reset(modulus);
				using MontgomeryContext fresh = kernel.Create(modulus);

				if (!ComputeAlike(context, fresh, random))
				{
					failures.Add($"{limbs} limbs: {n:X}");
				}
			}
		}

		return failures;
	}

	// The modulus, its constants, and the results of each operation on the same values.
	private static bool ComputeAlike(MontgomeryContext context, MontgomeryContext other, Random random)
	{
		int limbs = context.LimbCount;
		int digits = context.DigitCount;
		ulong[] x = ToLimbs(RandomBits(random, 64 * limbs), limbs);
		ulong[] y = ToLimbs(RandomBits(random, 64 * limbs), limbs);
		ulong[] exponent = ToLimbs(RandomBits(random, 128), 2);
		ulong[][] results = [.. Enumerable.Range(0, 2).Select(_ => new ulong[6 * digits + 3 * limbs])];

		for (int i = 0; i < 2; ++i)
		{
			MontgomeryContext c = i is 0 ? context : other;
			Span<ulong> rest = results[i];
			Span<ulong> one = rest.Slice(0, digits);
			Span<ulong> xm = rest.Slice(digits, digits);
			Span<ulong> ym = rest.Slice(2 * digits, digits);
			Span<ulong> product = rest.Slice(3 * digits, digits);
			Span<ulong> difference = rest.Slice(4 * digits, digits);
			Span<ulong> power = rest.Slice(5 * digits, digits);
			Span<ulong> modulus = rest.Slice(6 * digits, limbs);
			Span<ulong> rSquared = rest.Slice(6 * digits + limbs, limbs);
			Span<ulong> plain = rest.Slice(6 * digits + 2 * limbs, limbs);
			c.Modulus.CopyTo(modulus);
			c.WriteOne(one);
			c.WriteRSquared(rSquared);
			c.ToMontgomery(x, xm);
			c.ToMontgomery(y, ym);
			c.Multiply(product, xm, ym);
			c.Subtract(difference, xm, ym);
			c.Exponentiate(xm, exponent, power);
			c.FromMontgomery(power, plain);
		}

		return results[0].AsSpan().SequenceEqual(results[1]);
	}

	// The limb counts of the kernel's LimbCountsToTest, or in full every one of LimbCounts that it holds.
	private static IEnumerable<int> LimbCountsOf(MontgomeryKernelCase kernel, bool full)
	{
		return full ? LimbCounts.Where(kernel.Fits) : kernel.LimbCountsToTest;
	}

	// Contexts for the moduli of ModuliToTest at the limb counts of LimbCountsOf up to maxLimbs, or in full for every modulus of Moduli at those of any length.
	private static IEnumerable<(MontgomeryContext Context, BigInteger Modulus)> Contexts(MontgomeryKernelCase kernel, Random random, bool full, int maxLimbs = int.MaxValue)
	{
		foreach (int limbs in LimbCountsOf(kernel, full).Where(limbs => full || limbs <= maxLimbs))
		{
			foreach (BigInteger n in full ? Moduli(random, limbs) : ModuliToTest(random, limbs))
			{
				yield return (kernel.Create(ToLimbs(n, limbs)), n);
			}
		}
	}

	// Values below 2n: the ends of [0, n) and [n, 2n) and random ones in both. Past MaxExponentiationLimbs, where the moduli only bound the sums, the outermost ends, unless full.
	private static BigInteger[] Elements(Random random, BigInteger n, bool full)
	{
		return full || n.GetBitLength() <= 64 * MaxExponentiationLimbs
			? [BigInteger.Zero, BigInteger.One, n - 1, n, n + 1, 2 * n - 1, RandomBelow(random, n), n + RandomBelow(random, n)]
			: [BigInteger.Zero, n - 1, n, 2 * n - 1];
	}

	private static void Check(List<string> failures, MontgomeryKernelCase kernel, ReadOnlySpan<ulong> element, BigInteger expected, BigInteger n, string description)
	{
		BigInteger value = ToBigInteger(element, kernel.DigitBits);

		foreach (ulong digit in element)
		{
			if (digit >> kernel.DigitBits is not 0)
			{
				failures.Add($"{description}: a digit is not reduced");
				return;
			}
		}

		if (value >= 2 * n || value % n != expected % n)
		{
			failures.Add($"{description}: {value:X}, expected {expected:X} mod n");
		}
	}
}
