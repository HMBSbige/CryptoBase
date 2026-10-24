using CryptoBase.Signatures.MLDsa;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.Signatures.MLDsa.MLDsaReference;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.MLDsa;

// Checks every kernel operation against MLDsaReference. Where IMLDsaKernel allows lazy reduction, an output passes if it is congruent modulo q and within the range the contract states, so that the same tests hold vector kernels that reduce differently; elsewhere it must be the exact value.
public class MLDsaKernelTest
{
	// The bound of Reduce, and the magnitude below which its result is the centered representative.
	private const int ReduceBound = 6283008;
	private const int CenteredBound = 2097409;

	// The largest input of Reduce and Power2Round.
	private const int LargestReducible = int.MaxValue - (1 << 22);

	private const int Sentinel = 0x5A5A5A5A;

	private const int MaxMismatches = 8;

	private static readonly int RModQ = (int)(R % Q);
	private static readonly int RInverse = Power(RModQ, Q - 2);
	private static readonly int[] Gamma2s = [MLDsaConstants.Gamma2Small, MLDsaConstants.Gamma2Large];
	private static readonly (int Gamma2, int Beta)[] ParameterSets =
	[
		(MLDsa44Parameters.Gamma2, Beta<MLDsa44Parameters>()),
		(MLDsa65Parameters.Gamma2, Beta<MLDsa65Parameters>()),
		(MLDsa87Parameters.Gamma2, Beta<MLDsa87Parameters>())
	];
	private static readonly int[] Etas = [2, 4];
	private static readonly int[] Gamma1BitCounts = [17, 19];

	// Positions at either end of each 128-, 256- and 512-bit vector and of the polynomial.
	private static readonly int[] Positions = [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 129, 191, 254, 255];

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(MLDsaKernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(IMLDsaKernel)));
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task NttMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		foreach (int[] f in Polynomials(new Random(1), Q - 1))
		{
			int[] actual = (int[])f.Clone();
			kernel.Ntt(actual);
			await AssertCongruent(actual, Ntt(f), 9L * Q);
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task InverseNttMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		foreach (int[] f in Polynomials(new Random(2), Q - 1))
		{
			int[] actual = (int[])f.Clone();
			kernel.InverseNtt(actual);
			await AssertCongruent(actual, Scale(InverseNtt(f), RModQ), Q);

			// NTT, Reduce and NTT⁻¹ as the caller chains them leave the R of NTT⁻¹.
			int[] roundTrip = (int[])f.Clone();
			kernel.Ntt(roundTrip);
			kernel.Reduce(roundTrip);
			kernel.InverseNtt(roundTrip);
			await AssertCongruent(roundTrip, Scale(f, RModQ), Q);
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task MultiplyAccumulateMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(3);

		for (int count = 1; count <= 8; ++count)
		{
			int[] a = RandomInts(random, count * N, Q);
			int[] b = RandomInts(random, count * N, 9 * Q);
			await VerifyMultiplyAccumulate(kernel, a, b, count);

			// Every product at its largest magnitude, all of one sign in each coefficient.
			int[] largestA = Enumerable.Range(0, count * N).Select(static i => i % 3 is 0 ? -(Q - 1) : Q - 1).ToArray();
			int[] largestB = Enumerable.Range(0, count * N).Select(static _ => 9 * Q - 1).ToArray();
			await VerifyMultiplyAccumulate(kernel, largestA, largestB, count);
		}
	}

	// NTT, Reduce, MultiplyAccumulate and NTT⁻¹ as the caller chains them give products in Z_q[X] / (X^256 + 1).
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task TransformedProductsMatchPolynomialProducts(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(4);

		for (int round = 0; round < 64; ++round)
		{
			int count = 1 + round % 8;
			int[] a = RandomInts(random, count * N, Q);
			int[] b = RandomInts(random, count * N, Q);
			int[] expected = new int[N];

			for (int j = 0; j < count; ++j)
			{
				expected = AddNtt(expected, MultiplyPolynomials(a.AsSpan(j * N, N), b.AsSpan(j * N, N)));
				kernel.Ntt(a.AsSpan(j * N, N));
				kernel.Reduce(a.AsSpan(j * N, N));
				kernel.Ntt(b.AsSpan(j * N, N));
			}

			int[] actual = new int[N];
			kernel.MultiplyAccumulate(a, b, actual, count);
			kernel.InverseNtt(actual);
			await AssertCongruent(actual, expected, Q);
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task ReduceMatchesContract(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(5);
		List<int> values = [-LargestReducible, 1 - LargestReducible, -1, 0, 1, Q - 1, Q, -Q, 1 - Q, 9 * Q - 1, 1 - 9 * Q, 255 * (Q - 1), -255 * (Q - 1), LargestReducible];

		// The quotient (a + 2^22) >> 23 steps at a = t · 2^23 − 2^22.
		for (long t = -255; t <= 256; ++t)
		{
			for (long delta = -1; delta <= 1; ++delta)
			{
				long value = t * (1 << 23) - (1 << 22) + delta;

				if (value is >= -LargestReducible and <= LargestReducible)
				{
					values.Add((int)value);
				}
			}
		}

		for (int value = -2048; value < 2048; ++value)
		{
			values.Add(value);
		}

		int[] f = new int[N];
		int[] actual = new int[N];
		List<string> mismatches = [];

		foreach (int[] chunk in Chunks(values.ToArray()))
		{
			chunk.CopyTo(f, 0);
			Check();
		}

		// Random values across the input range, with its ends at every position.
		for (int round = 0; round < 4096 && mismatches.Count < MaxMismatches; ++round)
		{
			for (int i = 0; i < N; ++i)
			{
				f[i] = random.Next(-LargestReducible, LargestReducible + 1);
			}

			f[round % N] = -LargestReducible;
			f[(round + N / 2) % N] = LargestReducible;
			Check();
		}

		await Assert.That(mismatches).IsEmpty();

		void Check()
		{
			f.CopyTo(actual, 0);
			kernel.Reduce(actual);

			for (int i = 0; i < N && mismatches.Count < MaxMismatches; ++i)
			{
				int centered = ModPlusMinus(f[i], Q);

				if (Math.Abs(actual[i]) > ReduceBound || Mod(actual[i]) != Mod(f[i]) || Math.Abs(centered) < CenteredBound && actual[i] != centered)
				{
					mismatches.Add($"Reduce({f[i]}) = {actual[i]}");
				}
			}
		}
	}

	[Test]
	public async Task MontgomeryReduceStaysBelowQ()
	{
		const long Bound = (1L << 31) * Q;
		Random random = new(20);
		List<string> mismatches = [];

		for (int i = 0; i < 1 << 20 && mismatches.Count < MaxMismatches; ++i)
		{
			long a = i switch
			{
				0 => Bound - 1,
				1 => 1 - Bound,
				_ => random.NextInt64(1 - Bound, Bound)
			};

			int reduced = MLDsaScalar.MontgomeryReduce(a);

			if (Math.Abs(reduced) >= Q || Mod((long)reduced * RModQ) != Mod(a))
			{
				mismatches.Add($"{a}: {reduced}");
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task AddInPlace(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(6);
		int[] left = RandomInts(random, N, 1 << 30);
		int[] right = RandomInts(random, N, 1 << 30);
		int[] sum = left.Zip(right, static (x, y) => x + y).ToArray();

		int[] destination = new int[N];
		kernel.Add(left, right, destination);
		await Assert.That(destination).IsEquivalentTo(sum, CollectionOrdering.Matching);

		int[] intoLeft = (int[])left.Clone();
		kernel.Add(intoLeft, right, intoLeft);
		await Assert.That(intoLeft).IsEquivalentTo(sum, CollectionOrdering.Matching);

		int[] intoRight = (int[])right.Clone();
		kernel.Add(left, intoRight, intoRight);
		await Assert.That(intoRight).IsEquivalentTo(sum, CollectionOrdering.Matching);
	}

	// The bounds that signing and verification check, and the largest the contract allows, crossed at every position.
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task ExceedsBoundMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(7);
		int[] bounds =
		[
			1,
			CenteredBound,
			MLDsa44Parameters.Gamma2,
			MLDsa65Parameters.Gamma2,
			MLDsa44Parameters.Gamma2 - Beta<MLDsa44Parameters>(),
			MLDsa65Parameters.Gamma2 - Beta<MLDsa65Parameters>(),
			MLDsa87Parameters.Gamma2 - Beta<MLDsa87Parameters>(),
			(1 << MLDsa44Parameters.Gamma1Bits) - Beta<MLDsa44Parameters>(),
			(1 << MLDsa65Parameters.Gamma1Bits) - Beta<MLDsa65Parameters>(),
			(1 << MLDsa87Parameters.Gamma1Bits) - Beta<MLDsa87Parameters>()
		];

		foreach (int bound in bounds)
		{
			int[] inside = RandomInts(random, N, bound);
			List<string> mismatches = [];

			foreach (int[] f in (int[][])[inside, Enumerable.Repeat(bound - 1, N).ToArray(), Enumerable.Repeat(1 - bound, N).ToArray()])
			{
				if (kernel.ExceedsBound(f, bound))
				{
					mismatches.Add($"bound {bound}, every |f_i| < bound: expected False");
				}
			}

			foreach (int position in Positions)
			{
				foreach (int value in (int[])[bound, -bound, bound - 1, 1 - bound, bound + 1, -bound - 1, ReduceBound, -ReduceBound])
				{
					int[] f = (int[])inside.Clone();
					f[position] = value;
					bool expected = Math.Abs(value) >= bound;

					if (kernel.ExceedsBound(f, bound) != expected)
					{
						mismatches.Add($"bound {bound}, [{position}] = {value}: expected {expected}");
					}
				}
			}

			await Assert.That(mismatches).IsEmpty();
		}
	}

	// The fused operations give the values of Add or Subtract then Reduce, and the answer of ExceedsBound on them, in place too.
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task FusedReduceExceedsBoundMatchesParts(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(8);
		int[] bounds = [1, CenteredBound, MLDsa44Parameters.Gamma2 - Beta<MLDsa44Parameters>(), (1 << MLDsa65Parameters.Gamma1Bits) - Beta<MLDsa65Parameters>()];
		List<string> mismatches = [];

		foreach (int bound in bounds)
		{
			for (int round = 0; round < 64 && mismatches.Count < MaxMismatches; ++round)
			{
				// Sums and differences within the input of Reduce: small ones that stay below the bound, with the bound itself at one position in every other round, or large ones that mostly reach it.
				int limit = round % 2 is 0 ? bound / 2 + 1 : 1 << 29;
				int[] left = RandomInts(random, N, limit);
				int[] right = RandomInts(random, N, limit);

				if (round % 4 is 2)
				{
					left[Positions[round % Positions.Length]] = bound;
					right[Positions[round % Positions.Length]] = 0;
				}

				int[] sum = left.Zip(right, static (x, y) => x + y).ToArray();
				kernel.Reduce(sum);
				int[] difference = left.Zip(right, static (x, y) => x - y).ToArray();
				kernel.Reduce(difference);
				int[] reduced = (int[])left.Clone();
				kernel.Reduce(reduced);

				int[] actual = new int[N];
				Check("Add", kernel.AddReduceExceedsBound(left, right, actual, bound), sum, actual);
				actual = (int[])left.Clone();
				Check("Add into left", kernel.AddReduceExceedsBound(actual, right, actual, bound), sum, actual);
				actual = (int[])right.Clone();
				Check("Add into right", kernel.AddReduceExceedsBound(left, actual, actual, bound), sum, actual);

				actual = new int[N];
				Check("Subtract", kernel.SubtractReduceExceedsBound(left, right, actual, bound), difference, actual);
				actual = (int[])left.Clone();
				Check("Subtract into left", kernel.SubtractReduceExceedsBound(actual, right, actual, bound), difference, actual);
				actual = (int[])right.Clone();
				Check("Subtract into right", kernel.SubtractReduceExceedsBound(left, actual, actual, bound), difference, actual);

				actual = (int[])left.Clone();
				Check("Reduce", kernel.ReduceExceedsBound(actual, bound), reduced, actual);

				void Check(string name, bool exceeds, int[] expected, int[] values)
				{
					if (exceeds != kernel.ExceedsBound(expected, bound) || !values.AsSpan().SequenceEqual(expected))
					{
						mismatches.Add($"{name}, bound {bound}, round {round}");
					}
				}
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task Power2RoundMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(8);
		int[] t = new int[N];
		int[] high = new int[N];
		int[] low = new int[N];
		List<string> mismatches = [];

		for (long first = 1 - Q; first < Q && mismatches.Count < MaxMismatches; first += N)
		{
			FillConsecutive(t, first, Q - 1);
			Check();
		}

		// Each residue where r0 = r mod± 2^13 changes sign or wraps, plus a multiple of q.
		List<int> values = [];

		for (int k = 0; k <= Q >> D; ++k)
		{
			foreach (int delta in (int[])[-(1 << D - 1) - 1, -(1 << D - 1), 1 - (1 << D - 1), -1, 0, 1, (1 << D - 1) - 1, 1 << D - 1, (1 << D - 1) + 1])
			{
				int residue = (k << D) + delta;

				if (residue is >= 0 and < Q)
				{
					values.Add(residue + random.Next(1, 250) * Q);
				}
			}
		}

		foreach (int[] chunk in Chunks(values.ToArray()))
		{
			chunk.CopyTo(t, 0);
			Check();
		}

		// Random values across the input range, with its ends at every position.
		for (int round = 0; round < 4096 && mismatches.Count < MaxMismatches; ++round)
		{
			for (int i = 0; i < N; ++i)
			{
				t[i] = random.Next(-LargestReducible, LargestReducible + 1);
			}

			t[round % N] = -LargestReducible;
			t[(round + N / 2) % N] = LargestReducible;
			Check();
		}

		await Assert.That(mismatches).IsEmpty();

		void Check()
		{
			kernel.Power2Round(t, high, low);

			for (int i = 0; i < N && mismatches.Count < MaxMismatches; ++i)
			{
				(int expectedHigh, int expectedLow) = Power2Round(t[i]);

				if (high[i] != expectedHigh || low[i] != expectedLow)
				{
					mismatches.Add($"t = {t[i]}: ({high[i]}, {low[i]}) instead of ({expectedHigh}, {expectedLow})");
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task DecomposeMatchesReferenceForEveryInput(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int[] r = new int[N];
		int[] high = new int[N];
		int[] low = new int[N];
		List<string> mismatches = [];

		foreach (int gamma2 in Gamma2s)
		{
			for (long first = 1 - Q; first < Q && mismatches.Count < MaxMismatches; first += N)
			{
				FillConsecutive(r, first, Q - 1);
				kernel.Decompose(r, high, low, gamma2);

				for (int i = 0; i < N && mismatches.Count < MaxMismatches; ++i)
				{
					(int expectedHigh, int expectedLow) = Decompose(r[i], gamma2);

					if (high[i] != expectedHigh || low[i] != expectedLow)
					{
						mismatches.Add($"γ2 = {gamma2}, r = {r[i]}: ({high[i]}, {low[i]}) instead of ({expectedHigh}, {expectedLow})");
					}
				}
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	// Algorithm 39 for r = high · 2γ2 + low with z = −low, so that r + z = high · 2γ2 has the HighBits high, over every high and every |low| < 2γ2. high varies across the lanes, so that over all shifts each low meets every high.
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task MakeHintMatchesReferenceForEveryInput(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(10);
		int[] low = new int[N];
		int[] high = new int[N];
		int[] hint = new int[N];
		int[] inPlace = new int[N];
		List<string> mismatches = [];

		foreach (int gamma2 in Gamma2s)
		{
			int m = (Q - 1) / (2 * gamma2);

			for (int shift = 0; shift < m && mismatches.Count < MaxMismatches; ++shift)
			{
				for (int i = 0; i < N; ++i)
				{
					high[i] = (shift + i) % m;
				}

				for (long first = 1 - 2 * gamma2; first < 2 * gamma2 && mismatches.Count < MaxMismatches; first += N)
				{
					FillConsecutive(low, first, 2 * gamma2 - 1);
					low.CopyTo(inPlace, 0);
					int count = kernel.MakeHint(low, high, hint, gamma2);
					int inPlaceCount = kernel.MakeHint(inPlace, high, inPlace, gamma2);
					int expectedCount = 0;

					for (int i = 0; i < N; ++i)
					{
						int expected = MakeHint(-low[i], (long)high[i] * 2 * gamma2 + low[i], gamma2);
						expectedCount += expected;

						if ((hint[i] != expected || inPlace[i] != expected) && mismatches.Count < MaxMismatches)
						{
							mismatches.Add($"γ2 = {gamma2}, high = {high[i]}, low = {low[i]}: {hint[i]} and in place {inPlace[i]} instead of {expected}");
						}
					}

					if (count != expectedCount || inPlaceCount != expectedCount)
					{
						mismatches.Add($"γ2 = {gamma2}, low from {first}: {count} and in place {inPlaceCount} hints counted instead of {expectedCount}");
					}
				}
			}

			// Low bits of 2γ2 or more need only give a bit, which the count must add up.
			int[] anyLow = [.. RandomInts(random, N - 4, int.MaxValue), int.MinValue, int.MaxValue, 2 * gamma2, -2 * gamma2];
			int[] anyHigh = Enumerable.Range(0, N).Select(_ => random.Next(m)).ToArray();
			int[] bits = new int[N];
			int bitCount = kernel.MakeHint(anyLow, anyHigh, bits, gamma2);

			using (Assert.Multiple())
			{
				await Assert.That(bits).All(static value => value is 0 or 1);
				await Assert.That(bitCount).IsEqualTo(bits.Sum());
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	// Each r in (−q, q) with either hint, the hints of a polynomial random, then their complement.
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task UseHintMatchesReferenceForEveryInput(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(11);
		int[] r = new int[N];
		int[] hint = new int[N];
		int[] actual = new int[N];
		int[] inPlace = new int[N];
		List<string> mismatches = [];

		foreach (int gamma2 in Gamma2s)
		{
			int[] pattern = Enumerable.Range(0, N).Select(_ => random.Next(2)).ToArray();

			foreach (int flip in (int[])[0, 1])
			{
				for (int i = 0; i < N; ++i)
				{
					hint[i] = pattern[i] ^ flip;
				}

				for (long first = 1 - Q; first < Q && mismatches.Count < MaxMismatches; first += N)
				{
					FillConsecutive(r, first, Q - 1);
					r.CopyTo(inPlace, 0);
					kernel.UseHint(r, hint, actual, gamma2);
					kernel.UseHint(inPlace, hint, inPlace, gamma2);

					for (int i = 0; i < N && mismatches.Count < MaxMismatches; ++i)
					{
						int expected = UseHint(hint[i], r[i], gamma2);

						if (actual[i] != expected || inPlace[i] != expected)
						{
							mismatches.Add($"γ2 = {gamma2}, h = {hint[i]}, r = {r[i]}: {actual[i]} and in place {inPlace[i]} instead of {expected}");
						}
					}
				}
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	// Signing checks w0 − ⟨⟨cs2⟩⟩ in place of LowBits(w − ⟨⟨cs2⟩⟩) and takes the hints from w0 − ⟨⟨cs2⟩⟩ + ⟨⟨ct0⟩⟩ and HighBits(w): the rejection must agree with Algorithm 7, line 23, each hint of a coefficient that passes with line 26, and UseHint must give back HighBits(w) from it (Algorithm 8, line 10).
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task HintsOfSigningMatchAlgorithm7(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		int[] w = new int[N];
		int[] w1 = new int[N];
		int[] w0 = new int[N];
		int[] cs2 = new int[N];
		int[] ct0 = new int[N];
		int[] low = new int[N];
		int[] hint = new int[N];
		List<string> mismatches = [];

		foreach ((int gamma2, int beta) in ParameterSets)
		{
			int m = (Q - 1) / (2 * gamma2);
			Random random = new(gamma2 + beta);

			for (int round = 0; round < 2048 && mismatches.Count < MaxMismatches; ++round)
			{
				for (int i = 0; i < N; ++i)
				{
					w[i] = random.Next(Q);
					cs2[i] = random.Next(-beta, beta + 1);
					ct0[i] = random.Next(1 - gamma2, gamma2);
				}

				if (round is 0)
				{
					FillEdges(w, cs2, ct0, gamma2, beta, m);
				}

				kernel.Decompose(w, w1, w0, gamma2);
				bool rejected = kernel.SubtractReduceExceedsBound(w0, cs2, low, gamma2 - beta);
				bool expectedRejected = false;

				for (int i = 0; i < N; ++i)
				{
					expectedRejected |= Math.Abs(LowBits((long)w[i] - cs2[i], gamma2)) >= gamma2 - beta;
				}

				if (rejected != expectedRejected)
				{
					mismatches.Add($"γ2 = {gamma2}, β = {beta}, round {round}: rejected {rejected} instead of {expectedRejected}");
				}

				kernel.Add(low, ct0, low);
				kernel.MakeHint(low, w1, hint, gamma2);

				for (int i = 0; i < N; ++i)
				{
					if (Math.Abs(w0[i] - cs2[i]) >= gamma2 - beta)
					{
						continue;
					}

					long r = (long)w[i] - cs2[i] + ct0[i];
					int expected = MakeHint(-ct0[i], r, gamma2);

					if (hint[i] != expected)
					{
						mismatches.Add($"γ2 = {gamma2}, w = {w[i]}, cs2 = {cs2[i]}, ct0 = {ct0[i]}: hint {hint[i]} instead of {expected}");
					}

					if (UseHint(expected, r, gamma2) != w1[i])
					{
						mismatches.Add($"γ2 = {gamma2}, w = {w[i]}, cs2 = {cs2[i]}, ct0 = {ct0[i]}: UseHint gives {UseHint(expected, r, gamma2)} instead of {w1[i]}");
					}
				}
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task RejectSampleMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(12);
		byte[] blocks = new byte[5 * 168];
		random.NextBytes(blocks);

		// 0, q − 1, q and 2^23 − 1, with the top bit of the third byte clear and set, in every lane.
		int[] edgeValues = [0, Q - 1, Q, (1 << 23) - 1, 1, Q - 2];
		byte[] edges = Enumerable.Range(0, 96).SelectMany(i => Candidate(edgeValues[i % edgeValues.Length], i / edgeValues.Length % 2 is 1)).ToArray();

		byte[][] sources = [blocks, blocks.AsSpan(0, 168).ToArray(), blocks.AsSpan(0, 3).ToArray(), [], edges, new byte[5 * 168], Enumerable.Repeat((byte)0xFF, 5 * 168).ToArray()];

		foreach (byte[] source in sources)
		{
			foreach (int capacity in (int[])[N, N - 1, 100, 7, 1, 0])
			{
				List<int> expected = MLDsaReference.RejectSample(source, capacity);
				int[] destination = new int[capacity + 16];
				destination.AsSpan().Fill(Sentinel);
				int count = kernel.RejectSample(source, destination.AsSpan(0, capacity));

				using (Assert.Multiple())
				{
					await Assert.That(count).IsEqualTo(expected.Count);
					await Assert.That(destination.AsSpan(0, expected.Count).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
					await Assert.That(destination.AsSpan(expected.Count).ToArray()).All(static value => value is Sentinel);
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task RejectEtaMatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(13);
		byte[] blocks = new byte[2 * 136];
		random.NextBytes(blocks);

		// Every byte, so every pair of half-bytes, including 8, 9, 14 and 15 at the bounds of acceptance.
		byte[] everyByte = Enumerable.Range(0, 256).Select(static b => (byte)b).ToArray();
		byte[] mostlyRejected = Enumerable.Range(0, 136).Select(i => (byte)(i % 17 is 0 ? random.Next(256) : 0xF9 + random.Next(7))).ToArray();
		byte[][] sources = [blocks, blocks.AsSpan(0, 136).ToArray(), blocks.AsSpan(0, 139).ToArray(), blocks.AsSpan(0, 5).ToArray(), [], everyByte, mostlyRejected, new byte[136], Enumerable.Repeat((byte)0xFF, 136).ToArray(), Enumerable.Repeat((byte)0x9E, 136).ToArray(), Enumerable.Repeat((byte)0x8F, 136).ToArray()];

		foreach (int eta in Etas)
		{
			foreach (byte[] source in sources)
			{
				foreach (int capacity in (int[])[N, N - 1, 100, 17, 16, 9, 8, 7, 5, 4, 3, 2, 1, 0])
				{
					List<int> expected = MLDsaReference.RejectEta(source, capacity, eta);
					int[] destination = new int[capacity + 16];
					destination.AsSpan().Fill(Sentinel);
					int count = kernel.RejectEta(source, destination.AsSpan(0, capacity), eta);

					// Up to eight slots past the count may hold values that are not samples.
					int untouched = Math.Min(expected.Count + 8, capacity);

					using (Assert.Multiple())
					{
						await Assert.That(count).IsEqualTo(expected.Count);
						await Assert.That(destination.AsSpan(0, expected.Count).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
						await Assert.That(destination.AsSpan(untouched).ToArray()).All(static value => value is Sentinel);
					}
				}
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task EncodeT1AndDecodeT1MatchReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(14);
		const int Largest = (1 << 10) - 1;

		foreach (int[] t1 in Chunks(Enumerable.Range(0, Largest + 1).ToArray()).Concat(RandomPolynomials(random, 0, Largest)))
		{
			byte[] expected = SimpleBitPack(t1, Largest);
			byte[] encoded = new byte[320 + 9];
			PrepareDestination(encoded);
			kernel.EncodeT1(t1, encoded);
			await AssertOutput(encoded, expected);

			int[] decoded = new int[N];
			kernel.DecodeT1(expected, decoded);
			await Assert.That(decoded).IsEquivalentTo(t1.Select(static x => x << D).ToArray(), CollectionOrdering.Matching);
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task EncodeT0MatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(15);
		const int Bound = 1 << D - 1;

		// The extremes alone and alternating, and packed values from the position: its 8 bits in the low ones and its low 5 bits in the high ones, and their complement, so that the bits of each joint differ between neighbours and over every byte.
		int[] lowest = Enumerable.Repeat(1 - Bound, N).ToArray();
		int[] highest = Enumerable.Repeat(Bound, N).ToArray();
		int[] alternating = Enumerable.Range(0, N).Select(static i => i % 2 is 0 ? 1 - Bound : Bound).ToArray();
		int[] alternatingOther = Enumerable.Range(0, N).Select(static i => i % 2 is 0 ? Bound : 1 - Bound).ToArray();
		int[] positional = Enumerable.Range(0, N).Select(static i => Bound - (i * 0x101 & 0x1FFF)).ToArray();
		int[] positionalComplement = Enumerable.Range(0, N).Select(static i => Bound - (~(i * 0x101) & 0x1FFF)).ToArray();
		int[][] edges = [lowest, highest, alternating, alternatingOther, positional, positionalComplement];

		foreach (int[] t0 in Chunks(Enumerable.Range(1 - Bound, 2 * Bound).ToArray()).Concat(RandomPolynomials(random, 1 - Bound, Bound)).Concat(edges))
		{
			byte[] encoded = new byte[416 + 9];
			PrepareDestination(encoded);
			kernel.EncodeT0(t0, encoded);
			await AssertOutput(encoded, BitPack(t0, Bound - 1, Bound));

			byte[] scalar = new byte[416];
			MLDsaScalar.EncodeT0(t0, scalar);
			await Assert.That(encoded.AsSpan(0, 416).ToArray()).IsEquivalentTo(scalar, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task EncodeEtaAndDecodeEtaMatchReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(16);

		foreach (int eta in Etas)
		{
			int length = 32 * BitLength(2 * eta);
			int[] cycle = Enumerable.Range(0, N).Select(i => i % (2 * eta + 1) - eta).ToArray();

			foreach (int[] s in RandomPolynomials(random, -eta, eta).Append(cycle))
			{
				byte[] expected = BitPack(s, eta, eta);
				byte[] encoded = new byte[length + 9];
				PrepareDestination(encoded);
				kernel.EncodeEta(s, encoded, eta);
				await AssertOutput(encoded, expected);
				await VerifyDecodeEta(kernel, expected, eta);
			}

			// Any bytes, and a value above 2η alone at each position.
			for (int i = 0; i < 4; ++i)
			{
				byte[] source = new byte[length];
				random.NextBytes(source);
				await VerifyDecodeEta(kernel, source, eta);
			}

			for (int position = 0; position < N; ++position)
			{
				int[] packed = new int[N];
				packed[position] = (1 << BitLength(2 * eta)) - 1 - position % (eta is 2 ? 3 : 7);
				await VerifyDecodeEta(kernel, SimpleBitPack(packed, (1 << BitLength(2 * eta)) - 1), eta);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task EncodeZAndDecodeZMatchReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(17);

		foreach (int gamma1Bits in Gamma1BitCounts)
		{
			int gamma1 = 1 << gamma1Bits;
			int length = 32 * (gamma1Bits + 1);
			int[] edgeValues = [1 - gamma1, gamma1, 0, 1, -1, gamma1 - 1, 2 - gamma1];
			int[] edges = Enumerable.Range(0, N).Select(i => edgeValues[i % edgeValues.Length]).ToArray();

			foreach (int[] z in RandomPolynomials(random, 1 - gamma1, gamma1).Append(edges))
			{
				byte[] expected = BitPack(z, gamma1 - 1, gamma1);
				byte[] encoded = new byte[length + 9];
				PrepareDestination(encoded);
				kernel.EncodeZ(z, encoded, gamma1Bits);
				await AssertOutput(encoded, expected);

				int[] decoded = new int[N];
				kernel.DecodeZ(expected, decoded, gamma1Bits);
				await Assert.That(decoded).IsEquivalentTo(z, CollectionOrdering.Matching);
			}

			for (int i = 0; i < 4; ++i)
			{
				byte[] source = new byte[length];
				random.NextBytes(source);
				int[] decoded = new int[N];
				kernel.DecodeZ(source, decoded, gamma1Bits);
				await Assert.That(decoded).IsEquivalentTo(BitUnpack(source, gamma1 - 1, gamma1), CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task EncodeW1MatchesReference(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(18);

		foreach (int gamma2 in Gamma2s)
		{
			int largest = (Q - 1) / (2 * gamma2) - 1;
			int length = 32 * BitLength(largest);
			int[] cycle = Enumerable.Range(0, N).Select(i => i % (largest + 1)).ToArray();

			foreach (int[] w1 in RandomPolynomials(random, 0, largest).Append(cycle))
			{
				byte[] encoded = new byte[length + 9];
				PrepareDestination(encoded);
				kernel.EncodeW1(w1, encoded, gamma2);
				await AssertOutput(encoded, SimpleBitPack(w1, largest));
			}
		}
	}

	// Vector kernels load and store whole registers, so inputs and outputs may end at an inaccessible page.
	[Test]
	[MethodDataSource(typeof(MLDsaKernelCase), nameof(MLDsaKernelCase.All))]
	public async Task StaysWithinBuffers(MLDsaKernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		GuardPageBuffer.SkipUnlessSupported();

		Random random = new(19);
		int[] f = RandomInts(random, N, Q);
		int[] g = RandomInts(random, N, Q);

		using (GuardPageBuffer first = new(N * sizeof(int)))
		using (GuardPageBuffer second = new(N * sizeof(int)))
		using (GuardPageBuffer third = new(N * sizeof(int)))
		{
			f.CopyTo(Ints(first));
			kernel.Ntt(Ints(first));
			await AssertCongruent(Ints(first).ToArray(), Ntt(f), 9L * Q);
			kernel.Reduce(Ints(first));
			kernel.InverseNtt(Ints(first));
			await AssertCongruent(Ints(first).ToArray(), Scale(f, RModQ), Q);

			f.CopyTo(Ints(first));
			g.CopyTo(Ints(second));
			kernel.MultiplyAccumulate(Ints(first), Ints(second), Ints(third), 1);
			await AssertCongruent(Ints(third).ToArray(), Scale(MultiplyNtt(f, g), RInverse), Q);
			kernel.Add(Ints(first), Ints(second), Ints(third));
			await Assert.That(Ints(third).ToArray()).IsEquivalentTo(f.Zip(g, static (a, b) => a + b).ToArray(), CollectionOrdering.Matching);
			int[] difference = f.Zip(g, static (a, b) => a - b).ToArray();
			kernel.Reduce(difference);
			await Assert.That(kernel.SubtractReduceExceedsBound(Ints(first), Ints(second), Ints(third), CenteredBound)).IsEqualTo(kernel.ExceedsBound(difference, CenteredBound));
			await Assert.That(Ints(third).ToArray()).IsEquivalentTo(difference, CollectionOrdering.Matching);
			await Assert.That(kernel.ExceedsBound(Ints(first), CenteredBound)).IsEqualTo(f.Any(static a => Math.Abs(a) >= CenteredBound));

			kernel.Power2Round(Ints(first), Ints(second), Ints(third));
			await Assert.That(Ints(second).ToArray()).IsEquivalentTo(f.Select(static a => Power2Round(a).R1).ToArray(), CollectionOrdering.Matching);

			foreach (int gamma2 in Gamma2s)
			{
				kernel.Decompose(Ints(first), Ints(second), Ints(third), gamma2);
				int[] highs = Ints(second).ToArray();
				int[] lows = Ints(third).ToArray();
				await Assert.That(lows).IsEquivalentTo(f.Select(a => Decompose(a, gamma2).R0).ToArray(), CollectionOrdering.Matching);

				int count = kernel.MakeHint(Ints(third), Ints(second), Ints(third), gamma2);
				int[] expectedHints = lows.Zip(highs, (l, h) => MakeHint(-l, (long)h * 2 * gamma2 + l, gamma2)).ToArray();
				await Assert.That(Ints(third).ToArray()).IsEquivalentTo(expectedHints, CollectionOrdering.Matching);
				await Assert.That(count).IsEqualTo(expectedHints.Sum());

				Ints(second).Fill(1);
				kernel.UseHint(Ints(first), Ints(second), Ints(third), gamma2);
				await Assert.That(Ints(third).ToArray()).IsEquivalentTo(f.Select(a => UseHint(1, a, gamma2)).ToArray(), CollectionOrdering.Matching);
			}
		}

		await VerifyEncodingsWithinBuffers(kernel, random);

		foreach (int length in (int[])[3, 168, 5 * 168])
		{
			using GuardPageBuffer source = new(length);
			random.NextBytes(source.Span);
			int[] destination = new int[N];
			int count = kernel.RejectSample(source.Span, destination);
			await Assert.That(count).IsEqualTo(MLDsaReference.RejectSample(source.Span, N).Count);
		}

		foreach (int eta in Etas)
		{
			foreach (int length in (int[])[1, 7, 136, 2 * 136])
			{
				using GuardPageBuffer source = new(length);
				random.NextBytes(source.Span);
				int[] destination = new int[N];
				int count = kernel.RejectEta(source.Span, destination, eta);
				await Assert.That(count).IsEqualTo(MLDsaReference.RejectEta(source.Span, N, eta).Count);
			}
		}
	}

	private static async Task VerifyEncodingsWithinBuffers(MLDsaKernelCase kernel, Random random)
	{
		int[] t1 = RandomPolynomials(random, 0, 1023).First();
		byte[] t1Encoding = SimpleBitPack(t1, 1023);

		using (GuardPageBuffer encoded = new(320))
		{
			kernel.EncodeT1(t1, encoded.Span);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(t1Encoding, CollectionOrdering.Matching);
			int[] decoded = new int[N];
			kernel.DecodeT1(encoded.Span, decoded);
			await Assert.That(decoded).IsEquivalentTo(t1.Select(static x => x << D).ToArray(), CollectionOrdering.Matching);
		}

		int[] t0 = RandomPolynomials(random, 1 - (1 << D - 1), 1 << D - 1).First();

		using (GuardPageBuffer encoded = new(416))
		{
			kernel.EncodeT0(t0, encoded.Span);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(BitPack(t0, (1 << D - 1) - 1, 1 << D - 1), CollectionOrdering.Matching);
		}

		foreach (int eta in Etas)
		{
			int[] s = RandomPolynomials(random, -eta, eta).First();
			using GuardPageBuffer encoded = new(32 * BitLength(2 * eta));
			kernel.EncodeEta(s, encoded.Span, eta);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(BitPack(s, eta, eta), CollectionOrdering.Matching);
			int[] decoded = new int[N];
			await Assert.That(kernel.DecodeEta(encoded.Span, decoded, eta)).IsTrue();
			await Assert.That(decoded).IsEquivalentTo(s, CollectionOrdering.Matching);
		}

		foreach (int gamma1Bits in Gamma1BitCounts)
		{
			int gamma1 = 1 << gamma1Bits;
			int[] z = RandomPolynomials(random, 1 - gamma1, gamma1).First();
			using GuardPageBuffer encoded = new(32 * (gamma1Bits + 1));
			kernel.EncodeZ(z, encoded.Span, gamma1Bits);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(BitPack(z, gamma1 - 1, gamma1), CollectionOrdering.Matching);
			int[] decoded = new int[N];
			kernel.DecodeZ(encoded.Span, decoded, gamma1Bits);
			await Assert.That(decoded).IsEquivalentTo(z, CollectionOrdering.Matching);
		}

		foreach (int gamma2 in Gamma2s)
		{
			int largest = (Q - 1) / (2 * gamma2) - 1;
			int[] w1 = RandomPolynomials(random, 0, largest).First();
			using GuardPageBuffer encoded = new(32 * BitLength(largest));
			kernel.EncodeW1(w1, encoded.Span, gamma2);
			await Assert.That(encoded.Span.ToArray()).IsEquivalentTo(SimpleBitPack(w1, largest), CollectionOrdering.Matching);
		}
	}

	private static Span<int> Ints(GuardPageBuffer buffer)
	{
		return MemoryMarshal.Cast<byte, int>(buffer.Span);
	}

	private static void SkipUnlessSupported(MLDsaKernelCase kernel)
	{
		if (!kernel.IsSupported)
		{
			Skip.Test($"{kernel} is not supported here.");
		}
	}

	private static async Task VerifyMultiplyAccumulate(MLDsaKernelCase kernel, int[] a, int[] b, int count)
	{
		int[] expected = new int[N];

		for (int j = 0; j < count; ++j)
		{
			expected = AddNtt(expected, MultiplyNtt(a.AsSpan(j * N, N), b.AsSpan(j * N, N)));
		}

		int[] destination = new int[N + 16];
		destination.AsSpan().Fill(Sentinel);
		kernel.MultiplyAccumulate(a, b, destination.AsSpan(0, N), count);

		using (Assert.Multiple())
		{
			await AssertCongruent(destination.AsSpan(0, N).ToArray(), Scale(expected, RInverse), Q);
			await Assert.That(destination.AsSpan(N).ToArray()).All(static value => value is Sentinel);
		}
	}

	private static async Task VerifyDecodeEta(MLDsaKernelCase kernel, byte[] source, int eta)
	{
		int[] packed = SimpleBitUnpack(source, (1 << BitLength(2 * eta)) - 1);
		int[] decoded = new int[N];
		bool valid = kernel.DecodeEta(source, decoded, eta);

		using (Assert.Multiple())
		{
			await Assert.That(valid).IsEqualTo(packed.All(v => v <= 2 * eta));
			await Assert.That(decoded).IsEquivalentTo(BitUnpack(source, eta, eta), CollectionOrdering.Matching);
		}
	}

	// A kernel output must be congruent to the expected value and below bound in magnitude.
	private static async Task AssertCongruent(int[] actual, int[] expected, long bound)
	{
		List<string> mismatches = [];

		for (int i = 0; i < expected.Length; ++i)
		{
			if (Math.Abs((long)actual[i]) >= bound || Mod(actual[i]) != Mod(expected[i]))
			{
				mismatches.Add($"[{i}] = {actual[i]}, expected {Mod(expected[i])} mod q below {bound}");
			}
		}

		await Assert.That(mismatches).IsEmpty();
	}

	private static void FillConsecutive(int[] values, long first, long last)
	{
		for (int i = 0; i < values.Length; ++i)
		{
			values[i] = (int)Math.Min(first + i, last);
		}
	}

	// Coefficients at the edges of every case of Decompose and MakeHint: w1 of 0, 1 and m − 1 with w0 at its ends, cs2 at ±β, and ct0 at ±(γ2 − 1), so that w0 − cs2 + ct0 reaches ±γ2.
	private static void FillEdges(int[] w, int[] cs2, int[] ct0, int gamma2, int beta, int m)
	{
		int i = 0;

		foreach (int w1 in (int[])[0, 1, m - 1])
		{
			foreach (int w0 in (int[])[1 - gamma2, -1, 0, 1, gamma2])
			{
				foreach (int e in (int[])[-beta, 0, beta])
				{
					foreach (int f in (int[])[1 - gamma2, 0, gamma2 - 1])
					{
						w[i] = Mod((long)w1 * 2 * gamma2 + w0);
						cs2[i] = e;
						ct0[i] = f;
						++i;
					}
				}
			}
		}
	}

	// Random polynomials with coefficients at most bound in magnitude, then ones at the bound, alternating and zero.
	private static IEnumerable<int[]> Polynomials(Random random, int bound)
	{
		for (int i = 0; i < 6; ++i)
		{
			yield return RandomInts(random, N, bound + 1);
		}

		yield return Enumerable.Repeat(bound, N).ToArray();
		yield return Enumerable.Repeat(-bound, N).ToArray();
		yield return Enumerable.Range(0, N).Select(i => i % 2 is 0 ? bound : -bound).ToArray();
		yield return new int[N];
	}

	// Polynomials with coefficients in [lowest, highest], random but for one at each end.
	private static IEnumerable<int[]> RandomPolynomials(Random random, int lowest, int highest)
	{
		for (int i = 0; i < 4; ++i)
		{
			int[] values = Enumerable.Range(0, N).Select(_ => random.Next(lowest, highest + 1)).ToArray();
			values[random.Next(N)] = lowest;
			values[random.Next(N)] = highest;
			yield return values;
		}
	}

	// Splits values into polynomials, padding the last with zeros.
	private static IEnumerable<int[]> Chunks(int[] values)
	{
		for (int first = 0; first < values.Length; first += N)
		{
			int[] chunk = new int[N];
			values.AsSpan(first, Math.Min(N, values.Length - first)).CopyTo(chunk);
			yield return chunk;
		}
	}

	// The three bytes of a RejNTTPoly candidate, the top bit of the last set as CoeffFromThreeBytes ignores it.
	private static byte[] Candidate(int value, bool topBit)
	{
		return [(byte)value, (byte)(value >> 8), (byte)(value >> 16 | (topBit ? 0x80 : 0))];
	}

	// Values in (−bound, bound).
	private static int[] RandomInts(Random random, int length, int bound)
	{
		return Enumerable.Range(0, length).Select(_ => random.Next(1 - bound, bound)).ToArray();
	}

	private static int[] Scale(int[] values, int factor)
	{
		return values.Select(x => Mod((long)x * factor)).ToArray();
	}

	private static int Beta<TParameters>() where TParameters : IMLDsaParameters
	{
		return TParameters.Tau * TParameters.Eta;
	}
}
