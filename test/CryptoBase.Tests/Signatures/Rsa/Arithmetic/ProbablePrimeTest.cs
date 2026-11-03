using CryptoBase.Signatures.Rsa;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using static CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// ProbablePrime.Search on scripted candidates, which pass or fail the tests before Miller-Rabin, or are drawn again, as the script says: whether the platform tests two at once or not, the prime it keeps and the failures that make it give up are those of testing one candidate after the other. Two lengths, of which every platform takes pairs at one at least and some take none at one.
internal class ProbablePrimeTest
{
	// Primes and composites of each length of Lengths, whose top two bits are set as those of the candidates are.
	private static readonly Dictionary<int, Lazy<(BigInteger[] Primes, BigInteger[] Composites)>> Values = Lengths().ToDictionary(static bits => bits, static bits => new Lazy<(BigInteger[], BigInteger[])>(() => ([.. Enumerable.Range(0, 3).Select(i => Prime(new Random(91 + i), bits))], [.. Enumerable.Range(0, 8).Select(i => Composite(new Random(95 + i), bits))])));

	public static IEnumerable<int> Lengths()
	{
		yield return 1024;
		yield return 1536;
	}

	// Each script: its candidates as (index into the primes, or −1 − index into the composites, what becomes of it before Miller-Rabin), the limit of failures, and the prime expected, or −1 for FAILURE.
	// A candidate drawn again is a prime, which would be kept if it were tested.
	public static IEnumerable<Func<(int Bits, string Name, (int Candidate, CandidateOutcome Outcome)[] Script, int Limit, int Expected)>> Scripts()
	{
		const CandidateOutcome Pass = CandidateOutcome.Pass;
		const CandidateOutcome Fail = CandidateOutcome.Fail;
		const CandidateOutcome Redraw = CandidateOutcome.Redraw;

		foreach (int bits in Lengths())
		{
			yield return () => (bits, "the first candidate", [(0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "the first of the second pair", [(-1, Pass), (-2, Pass), (0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "the second of a pair", [(-1, Pass), (0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "a prime that fails the tests before Miller-Rabin", [(0, Fail), (-1, Pass), (1, Pass), (2, Pass)], 10, 1);
			yield return () => (bits, "a prime after failures before Miller-Rabin", [(-1, Fail), (-2, Fail), (2, Pass), (0, Pass)], 10, 2);
			yield return () => (bits, "the first with the limit after it", [(0, Pass), (-1, Fail), (-2, Fail), (-3, Fail)], 2, 0);
			yield return () => (bits, "the second at the limit", [(-1, Pass), (0, Pass)], 2, 0);
			yield return () => (bits, "the limit before the second", [(-1, Pass), (0, Pass)], 1, -1);
			yield return () => (bits, "the limit in failures before Miller-Rabin", [(-1, Pass), (-2, Fail), (-3, Fail), (0, Pass)], 3, -1);
			yield return () => (bits, "the limit in composites", [(-1, Pass), (-2, Pass), (-3, Pass), (-4, Pass), (0, Pass)], 4, -1);
			yield return () => (bits, "the limit just after a prime", [(-1, Pass), (-2, Pass), (-3, Pass), (0, Pass), (-4, Pass)], 4, 0);
			yield return () => (bits, "a prime after ten times the limit drawn again", [.. Enumerable.Repeat((1, Redraw), 30), (0, Pass), (2, Pass)], 3, 0);
			yield return () => (bits, "a prime with failures short of the limit and draws again around them", [(1, Redraw), (-1, Fail), (1, Redraw), (1, Redraw), (-2, Fail), (1, Redraw), (0, Pass), (2, Pass)], 3, 0);
			yield return () => (bits, "draws again while the first of a pair is pending", [(-1, Pass), (1, Redraw), (1, Redraw), (0, Pass)], 2, 0);
			yield return () => (bits, "the limit in failures with draws again between them", [(-1, Fail), (1, Redraw), (-2, Fail), (1, Redraw), (-3, Pass), (0, Pass)], 3, -1);
		}
	}

	[Test]
	[MethodDataSource(nameof(Scripts))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task KeepsWhatOneAfterTheOtherKeeps(int bits, string name, (int Candidate, CandidateOutcome Outcome)[] script, int limit, int expected)
	{
		(BigInteger[] primes, BigInteger[] composites) = Values[bits].Value;
		int limbs = bits / 64;
		int next = 0;
		ulong[] result = new ulong[limbs];

		CandidateOutcome Source(Span<ulong> value, ReadOnlySpan<ulong> other)
		{
			if (next >= script.Length)
			{
				throw new InvalidOperationException($"{name}: the script ran out.");
			}

			(int candidate, CandidateOutcome outcome) = script[next++];
			ToLimbs(candidate >= 0 ? primes[candidate] : composites[-1 - candidate], limbs).CopyTo(value);
			return outcome;
		}

		using Search search = new(limbs, bits, Source);

		if (expected < 0)
		{
			await Assert.That(search.Find(result, default, limit)).IsFalse();
		}
		else
		{
			await Assert.That(search.Find(result, default, limit)).IsTrue();
			await Assert.That(ToBigInteger(result)).IsEqualTo(primes[expected]);
		}
	}

	// A search goes on from one prime to the next with the contexts of its slots, which take every candidate in turn, and passes the prime before to the source. Each search takes candidates of its own; the one after its prime may be drawn while the prime is pending, and is not kept.
	[Test]
	[MethodDataSource(nameof(Lengths))]
	[SuppressMessage("ReSharper", "AccessToModifiedClosure", Justification = "Source reads the candidates and the prime that each turn of the loop sets.")]
	public async Task FindsOnePrimeAfterAnother(int bits)
	{
		(BigInteger[] primes, BigInteger[] composites) = Values[bits].Value;
		int limbs = bits / 64;
		Queue<BigInteger> candidates = [];
		BigInteger before = BigInteger.Zero;
		List<string> failures = [];

		CandidateOutcome Source(Span<ulong> value, ReadOnlySpan<ulong> other)
		{
			if ((other.IsEmpty ? BigInteger.Zero : ToBigInteger(other)) != before)
			{
				failures.Add($"other was not {before:X}");
			}

			ToLimbs(candidates.Dequeue(), limbs).CopyTo(value);
			return CandidateOutcome.Pass;
		}

		using Search search = new(limbs, bits, Source);
		BigInteger[][] scripts = [[composites[0], primes[0], composites[1]], [composites[2], composites[3], primes[1], composites[4]], [primes[2], composites[5]]];
		ulong[] previous = [];

		for (int i = 0; i < scripts.Length; ++i)
		{
			candidates = new Queue<BigInteger>(scripts[i]);
			ulong[] result = new ulong[limbs];

			if (!search.Find(result, previous, 10) || ToBigInteger(result) != primes[i])
			{
				failures.Add($"search {i} kept {ToBigInteger(result):X}");
			}

			previous = result;
			before = ToBigInteger(result);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Dispose erases what the search keeps of its candidates, the last of which is the prime that it found: the values of each slot, the number of trailing zeros of w − 1, and the contexts, whose −n⁻¹ mod 2^DigitBits gives the low bits of w.
	[Test]
	[MethodDataSource(nameof(Lengths))]
	public async Task DisposeErasesTheCandidates(int bits)
	{
		BigInteger prime = Values[bits].Value.Primes[0];
		int limbs = bits / 64;
		ulong[] result = new ulong[limbs];
		Search search = new(limbs, bits, (value, _) =>
		{
			ToLimbs(prime, limbs).CopyTo(value);
			return CandidateOutcome.Pass;
		});
		bool found = search.Find(result, default, 10);
		search.Dispose();
		List<string> failures = found ? [] : ["no prime was found"];

		foreach (string slot in (string[])["_first", "_second"])
		{
			object candidate = GetField(search, slot) ?? throw new InvalidOperationException($"{slot} is null.");
			object context = candidate.GetType().GetProperty("Context", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(candidate) ?? throw new InvalidOperationException($"{slot} has no context.");
			failures.AddRange(NonZeroWords(candidate).Concat(NonZeroWords(context)).Select(field => $"{slot}: {field}"));

			if (GetField(candidate, "_a") is not 0)
			{
				failures.Add($"{slot}: _a");
			}
		}

		if (GetField(search, "_pair") is { } pair)
		{
			failures.AddRange(NonZeroWords(pair).Select(field => $"_pair: {field}"));
		}

		await Assert.That(failures).IsEmpty();
	}

	// A run of Appendix A.1.3 that reaches a limit returns FAILURE, here at q, and Generate runs it again from the start with a new source, up to four runs: the next run searches p anew, and the search of q takes the p of its own run. After the fourth, Generate throws, with p and q zero.
	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(3)]
	[Arguments(4)]
	public async Task GenerateRunsAgainFromTheStart(int failingRuns)
	{
		const int Nlen = 2048;
		(BigInteger[] primes, _) = Values[Nlen / 2].Value;
		int limbs = Nlen / 128;
		int runs = 0;
		// The p that each search of q is given, without repeats.
		List<BigInteger> others = [];
		ulong[] p = new ulong[limbs];
		ulong[] q = new ulong[limbs];

		// A failing run finds primes[2] for p and fails every candidate for q; the last finds primes[0] and primes[1].
		CandidateSource CreateSource()
		{
			bool fails = ++runs <= failingRuns;

			return (value, other) =>
			{
				if (!other.IsEmpty)
				{
					BigInteger before = ToBigInteger(other);

					if (others.Count is 0 || others[^1] != before)
					{
						others.Add(before);
					}

					if (fails)
					{
						return CandidateOutcome.Fail;
					}
				}

				ToLimbs(other.IsEmpty ? primes[fails ? 2 : 0] : primes[1], limbs).CopyTo(value);
				return CandidateOutcome.Pass;
			};
		}

		if (failingRuns < 4)
		{
			Generate(Nlen, p, q, CreateSource);
			BigInteger[] expectedOthers = failingRuns is 0 ? [primes[0]] : [primes[2], primes[0]];

			using (Assert.Multiple())
			{
				await Assert.That(runs).IsEqualTo(failingRuns + 1);
				await Assert.That((ToBigInteger(p), ToBigInteger(q))).IsEqualTo((primes[0], primes[1]));
				await Assert.That(others).IsEquivalentTo(expectedOthers, CollectionOrdering.Matching);
			}
		}
		else
		{
			await Assert.That(() => Generate(Nlen, p, q, CreateSource)).Throws<CryptographicException>();

			using (Assert.Multiple())
			{
				await Assert.That(runs).IsEqualTo(4);
				await Assert.That(p.Concat(q).All(static word => word is 0)).IsTrue();
			}
		}
	}

	// Bases are uniform in [2, w − 2] for the least w whose top two bits are set, where draws fall above w − 2 most often, at a length of a partial limb: neither a draw out of range nor the bits above the length reach a base.
	[Test]
	public async Task BasesAreUniformInRange()
	{
		const int Bits = 1028;
		const int Samples = 3000;
		int limbs = (Bits + 63) / 64;
		BigInteger w = BigInteger.One << Bits - 1 | BigInteger.One << Bits - 2 | 1;
		ulong[] wMinusOne = ToLimbs(w - 1, limbs);
		ulong[] b = new ulong[limbs];
		int[] tops = new int[4];
		int[] lows = new int[16];
		int outOfRange = 0;

		for (int i = 0; i < Samples; ++i)
		{
			SampleBase(b, wMinusOne, Bits);
			BigInteger value = ToBigInteger(b);
			outOfRange += value < 2 || value > w - 2 ? 1 : 0;
			++tops[(int)(value >> Bits - 2)];
			++lows[(int)(value & 15)];
		}

		// Below 3·2^(Bits − 2), the top two bits take three values alike; χ² bounds of 2 and 15 degrees of freedom that a uniform base exceeds with probability below 10^-6.
		double topChiSquare = tops.Take(3).Sum(static count => Math.Pow(count - Samples / 3.0, 2) / (Samples / 3.0));
		double lowChiSquare = lows.Sum(static count => Math.Pow(count - Samples / 16.0, 2) / (Samples / 16.0));

		using (Assert.Multiple())
		{
			await Assert.That(outOfRange).IsEqualTo(0);
			await Assert.That(tops[3]).IsEqualTo(0);
			await Assert.That(topChiSquare).IsLessThan(28);
			await Assert.That(lowChiSquare).IsLessThan(58);
		}
	}

	// A key takes little memory beyond that of the key itself, whatever the candidates it goes through: the contexts and buffers of the candidates last for the key.
	[Test]
	[NotInParallel]
	public async Task GenerateAllocatesLittlePerKey()
	{
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		long before = GC.GetAllocatedBytesForCurrentThread();
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		long perKey = (GC.GetAllocatedBytesForCurrentThread() - before) / 2;

		await Assert.That(perKey).IsLessThan(64 * 1024);
	}

	private static BigInteger Prime(Random random, int bits)
	{
		while (true)
		{
			BigInteger candidate = RandomBits(random, bits) | BigInteger.One << bits - 1 | BigInteger.One << bits - 2 | 1;

			if (IsProbablePrime(candidate, random))
			{
				return candidate;
			}
		}
	}

	private static BigInteger Composite(Random random, int bits)
	{
		while (true)
		{
			BigInteger candidate = RandomBits(random, bits) | BigInteger.One << bits - 1 | BigInteger.One << bits - 2 | 1;

			if (!IsProbablePrime(candidate, random, 4))
			{
				return candidate;
			}
		}
	}
}
