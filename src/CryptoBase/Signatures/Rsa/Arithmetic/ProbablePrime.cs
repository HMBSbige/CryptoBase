using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The random probable primes p and q of FIPS 186-5, Appendix A.1.3, for a modulus of nlen bits, each of nlen/2 bits, tested by trial division (Appendix B.3, see TrialDivision) and the Miller-Rabin test of Appendix B.3.1.
// Every candidate is drawn afresh, so a rejected one tells nothing of the prime that is kept: the checks of a candidate stop at the first that fails, and the time of each check, which must not depend on the candidate, is all that an accepted one reveals.
// Where the platform exponentiates two moduli of the length of the candidates at once, with the contexts that it takes for one (see MontgomeryKernelDispatch.CreatePair), the first rounds of the Miller-Rabin tests of two candidates in a row exponentiate together, and the rest of the tests follow in the order of the candidates: the first that passes is kept, as one candidate after the other would keep it, and a later one only takes time.
internal static class ProbablePrime
{
	// Bases per batch of the Miller-Rabin test; see SampleBase.
	private const int BasesPerBatch = 33;

	// Runs of Appendix A.1.3 before Generate gives up; see Generate.
	private const int MaxRuns = 4;

	// Fills p and q, of ⌈nlen/128⌉ limbs, for nlen from 2048 to 16384, a multiple of 8, and an odd e with 2^16 < e < 2^33.
	// A run of Appendix A.1.3 returns FAILURE once 5·nlen candidates for p fail (step 4.7), or 10·nlen for q (step 5.8). Some 20/ln 2 ≈ 28.9 of the candidates for p are prime at every nlen, and for e = 65537 almost every prime passes step 4.5, so that a run fails with probability about e^-28.9 ≈ 2^-41.6, and four in a row with about 2^-166; an e with small prime factors, which more primes share with p − 1, makes it likelier. Generate runs it again from the start, up to four runs in all, and throws CryptographicException after the fourth.
	internal static void Generate(int nlen, ulong e, Span<ulong> p, Span<ulong> q)
	{
		int bits = nlen / 2;
		int limbs = (bits + 63) / 64;

		Debug.Assert(p.Length == limbs && q.Length == limbs && nlen % 8 is 0 && (e & 1) is 1);

		Generate(nlen, p, q, () =>
		{
			TrialDivision trial = new(limbs);
			return (value, other) => DrawCandidate(value, bits, e, trial, other);
		});
	}

	// Generate with the candidates of a source that createSource makes for each run: a run takes nothing from the one before it, and p and q are zero after the last fails.
	internal static void Generate(int nlen, Span<ulong> p, Span<ulong> q, Func<CandidateSource> createSource)
	{
		int bits = nlen / 2;
		int limbs = (bits + 63) / 64;

		for (int run = 0; run < MaxRuns; ++run)
		{
			p.Clear();
			q.Clear();
			using Search search = new(limbs, bits, createSource());

			// Steps 4.1 to 4.7, with the failures counted until 5·nlen, then steps 5.1 to 5.8, until 10·nlen.
			if (search.Find(p, default, 5 * nlen) && search.Find(q, p, 10 * nlen))
			{
				return;
			}
		}

		p.Clear();
		q.Clear();
		throw new CryptographicException("No primes were found.");
	}

	// Table B.1 gives 5 rounds for 1024-bit primes (error probability 2^-112), and 4 for 1536 and 2048 bits (2^-128 and 2^-144); the bound of Appendix C.1 only falls as the primes grow, and gives at most 2^-192 for 3840 bits and 2^-256 for 7680 bits, the security strengths of 7680- and 15360-bit moduli, within 4 rounds.
	internal static int GetRounds(int bits)
	{
		return bits < 1536 ? 5 : 4;
	}

	// Draws a candidate into value (steps 4.2 to 4.4, or 5.2 to 5.5 after p), and runs the tests of step 4.5 or 5.6 that come before the Miller-Rabin test on it.
	private static CandidateOutcome DrawCandidate(Span<ulong> value, int bits, ulong e, TrialDivision trial, ReadOnlySpan<ulong> other)
	{
		// Step 4.2: bits random bits. Step 4.2.1: the top two set, which also makes p ≥ 3·2^(bits−2) > √2·2^(bits−1), as step 4.4 requires, and the modulus nlen bits long. Step 4.3: p odd.
		DrawBits(value, bits);
		value[(bits - 1) / 64] |= 1UL << (bits - 1) % 64;
		value[(bits - 2) / 64] |= 1UL << (bits - 2) % 64;
		value[0] |= 1;

		// Step 5.5: |p − q| > 2^(nlen/2 − 100), or back to step 5.2.
		if (!other.IsEmpty && !IsFarEnough(value, other, bits))
		{
			return CandidateOutcome.Redraw;
		}

		// Step 4.5: GCD(p − 1, e) = 1, and the trial division that Appendix B.3 allows before the primality test.
		return !trial.HasSmallFactor(value) && IsCoprimeMinusOne(value, e) is not 0 ? CandidateOutcome.Pass : CandidateOutcome.Fail;
	}

	// |x − y| > 2^(bits − 100).
	private static bool IsFarEnough(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, int bits)
	{
		int limbs = x.Length;
		int bufferLength = 3 * limbs;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> difference = buffer.Span.Slice(0, limbs);
		Span<ulong> negated = buffer.Span.Slice(limbs, limbs);
		Span<ulong> bound = buffer.Span.Slice(2 * limbs, limbs);
		ulong borrow = Limbs.Subtract(x, y, difference);
		_ = Limbs.Subtract(y, x, negated);
		Limbs.Select(0 - borrow, negated, difference, difference);
		bound.Clear();
		bound[(bits - 100) / 64] = 1UL << (bits - 100) % 64;
		return Limbs.LessThan(bound, difference) is not 0;
	}

	// All ones if GCD(value − 1, e) = 1.
	private static ulong IsCoprimeMinusOne(ReadOnlySpan<ulong> value, ulong e)
	{
		ulong remainder = SmallModulus.Remainder(value, e);
		ulong minusOne = LimbArithmetic.Select(LimbArithmetic.ZeroMask(remainder), e - 1, remainder - 1);
		return SmallModulus.IsCoprime(minusOne, e);
	}

	// Steps 4.1 and 4.2: a base b of bits random bits with 1 < b < w − 1. Taking the first of several draws that falls in range gives the distribution of drawing again until one does, but the selection runs through every draw of a batch. The number of batches depends on w only where all draws of one fall outside the range, each with probability at most 1/4 + 2^(1 − bits) by the top two bits of w, which leaves a batch of 33 draws a probability below 2^-65 of taking another.
	// The draws of a batch come from one call for random bytes, each in the limbs that hold bits bits, with the bits above them cleared.
	internal static void SampleBase(Span<ulong> b, ReadOnlySpan<ulong> wMinusOne, int bits)
	{
		int limbs = b.Length;
		int bufferLength = BasesPerBatch * limbs;
		using CryptoBuffer<ulong> buffer = CryptoBuffer<ulong>.ShouldUsePool(bufferLength) ? new CryptoBuffer<ulong>(bufferLength) : new CryptoBuffer<ulong>(stackalloc ulong[bufferLength]);
		Span<ulong> draws = buffer.Span;
		ulong found = 0;
		Span<ulong> two = [2];

		Debug.Assert(limbs == (bits + 63) / 64);

		do
		{
			SystemRandom.Fill(MemoryMarshal.AsBytes(draws));

			for (int i = 0; i < BasesPerBatch; ++i)
			{
				Span<ulong> draw = draws.Slice(i * limbs, limbs);

				if (bits % 64 is not 0)
				{
					draw[^1] &= (1UL << bits % 64) - 1;
				}

				ulong inRange = ~Limbs.LessThan(draw, two) & Limbs.LessThan(draw, wMinusOne);
				Limbs.Select(inRange & ~found, draw, b, b);
				found |= inRange;
			}
		}
		while (found is 0);
	}

	// Random bits bits, in limbs that hold them, with the rest zero.
	private static void DrawBits(Span<ulong> value, int bits)
	{
		value.Clear();
		Span<byte> bytes = MemoryMarshal.AsBytes(value);
		SystemRandom.Fill(bytes.Slice(0, (bits + 7) / 8));

		if (!BitConverter.IsLittleEndian)
		{
			for (int i = 0; i < value.Length; ++i)
			{
				value[i] = BinaryPrimitives.ReverseEndianness(value[i]);
			}
		}

		if (bits % 64 is not 0)
		{
			value[bits / 64] &= (1UL << bits % 64) - 1;
		}
	}

	// What becomes of a candidate before the Miller-Rabin test: drawn again, as steps 4.4 and 5.5 go back to steps 4.2 and 5.2, which steps 4.6 and 5.7 do not count; failed, as steps 4.5 and 5.6 fail, which they count; or passed, for the Miller-Rabin test to decide.
	internal enum CandidateOutcome
	{
		Redraw,
		Fail,
		Pass
	}

	// Draws a fresh candidate into value and runs the tests before the Miller-Rabin test on it, with other the prime before it if not empty.
	internal delegate CandidateOutcome CandidateSource(Span<ulong> value, ReadOnlySpan<ulong> other);

	// The candidates of one key, with the contexts and buffers that every candidate takes in turn, and the pair context of the contexts of the two slots where the platform has one.
	internal sealed class Search : IDisposable
	{
		private readonly int _rounds;
		private readonly CandidateSource _source;
		private readonly MontgomeryPairContext? _pair;
		private readonly Candidate _first;
		private readonly Candidate _second;

		// For candidates of bits bits, whose top two bits are set, in limbs limbs.
		internal Search(int limbs, int bits, CandidateSource source)
		{
			_rounds = GetRounds(bits);
			_source = source;
			// Contexts of the limb count of the candidates, for a modulus that the first candidate of each slot replaces.
			ulong[] placeholder = new ulong[limbs];
			placeholder.AsSpan().Fill(ulong.MaxValue);
			_pair = MontgomeryKernelDispatch.CreatePair(placeholder, placeholder, out MontgomeryContext first, out MontgomeryContext second);
			MontgomeryContext single = MontgomeryKernelDispatch.Create(placeholder);

			// The candidate that passes runs most of its tests alone, which the contexts of a pair slow down where their digits are those of the pair kernel rather than the best for one modulus (see MontgomeryKernelDispatch.CreatePair): those take no pair.
			if (_pair is null || first.GetType() != single.GetType())
			{
				_pair?.Dispose();
				_pair = null;
				first.Dispose();
				second.Dispose();
				first = single;
				second = MontgomeryKernelDispatch.Create(placeholder);
			}
			else
			{
				single.Dispose();
			}

			_first = new Candidate(first, bits);
			_second = new Candidate(second, bits);
		}

		// Fills value with the first candidate that passes every test, after other if it is not empty, and returns false, for FAILURE, once limit candidates have failed, as one candidate after the other would; those drawn again do not count. The second of a pair is drawn while the first is pending, and only allowed the failures that would leave the first one to fail before the limit; its failures count after those of the first.
		internal bool Find(Span<ulong> value, ReadOnlySpan<ulong> other, int limit)
		{
			int failures = 0;

			while (true)
			{
				if (!Draw(_first, other, limit - failures, out int failed))
				{
					return false;
				}

				failures += failed;
				int skipped = 0;
				MontgomeryPairContext? pair = _pair is not null && Draw(_second, other, limit - failures - 1, out skipped) ? _pair : null;

				if (pair is not null)
				{
					pair.Reset(_first.Context, _second.Context);
					_first.SampleBase();
					_second.SampleBase();
					pair.Exponentiate(_first.Z, _first.M, _second.Z, _second.M, _first.Z, _second.Z);
				}
				else
				{
					_first.SampleBase();
					_first.Exponentiate();
				}

				if (_first.Finish(_rounds))
				{
					_first.Value.CopyTo(value);
					return true;
				}

				failures += 1 + skipped;

				if (failures >= limit)
				{
					return false;
				}

				if (pair is null)
				{
					continue;
				}

				if (_second.Finish(_rounds))
				{
					_second.Value.CopyTo(value);
					return true;
				}

				if (++failures >= limit)
				{
					return false;
				}
			}
		}

		public void Dispose()
		{
			_pair?.Dispose();
			_first.Dispose();
			_second.Dispose();
		}

		// Draws candidates into slot until one passes the tests before the Miller-Rabin test, which it prepares for, or until maxFailures fail them; failed counts those that fail, and not those drawn again.
		private bool Draw(Candidate slot, ReadOnlySpan<ulong> other, int maxFailures, out int failed)
		{
			failed = 0;

			while (failed < maxFailures)
			{
				CandidateOutcome outcome = _source(slot.Value, other);

				if (outcome is CandidateOutcome.Pass)
				{
					slot.Prepare();
					return true;
				}

				failed += outcome is CandidateOutcome.Fail ? 1 : 0;
			}

			return false;
		}
	}

	// A slot of Search: a candidate w with its context and the values of Appendix B.3.1, for one candidate after another.
	private sealed class Candidate : IDisposable
	{
		private readonly int _bits;
		private readonly int _limbs;
		private readonly int _digits;

		// w, w − 1, m and b in limbs, then z, 1 and −1 as elements and the scratch of a square.
		private readonly ulong[] _data;
		private int _a;

		internal Candidate(MontgomeryContext context, int bits)
		{
			Context = context;
			_bits = bits;
			_limbs = context.LimbCount;
			_digits = context.DigitCount;
			_data = new ulong[4 * _limbs + 3 * _digits + context.ScratchLength];
		}

		internal MontgomeryContext Context { get; }

		internal Span<ulong> Value => _data.AsSpan(0, _limbs);

		internal ReadOnlySpan<ulong> M => _data.AsSpan(2 * _limbs, _limbs);

		internal Span<ulong> Z => _data.AsSpan(4 * _limbs, _digits);

		private Span<ulong> WMinusOne => _data.AsSpan(_limbs, _limbs);

		private Span<ulong> B => _data.AsSpan(3 * _limbs, _limbs);

		private Span<ulong> One => _data.AsSpan(4 * _limbs + _digits, _digits);

		private Span<ulong> MinusOne => _data.AsSpan(4 * _limbs + 2 * _digits, _digits);

		private Span<ulong> Scratch => _data.AsSpan(4 * _limbs + 3 * _digits);

		// The context of w, and steps 1 and 2: w − 1 = 2^a·m with m odd.
		internal void Prepare()
		{
			Context.Reset(Value);
			Span<ulong> wMinusOne = WMinusOne;
			Span<ulong> m = _data.AsSpan(2 * _limbs, _limbs);
			Value.CopyTo(wMinusOne);
			_ = Limbs.SubtractSmall(wMinusOne, 1);
			_a = Limbs.TrailingZeroCount(wMinusOne);
			wMinusOne.CopyTo(m);
			Limbs.ShiftRight(m, _a);
			Context.WriteOne(One);
			Context.ToMontgomery(wMinusOne, MinusOne);
			Context.Reduce(MinusOne);
		}

		// Steps 4.1 and 4.2, and the base in Montgomery form in z for step 4.3.
		internal void SampleBase()
		{
			ProbablePrime.SampleBase(B, WMinusOne, _bits);
			Context.ToMontgomery(B, Z);
		}

		// Step 4.3: z = b^m.
		internal void Exponentiate()
		{
			Context.Exponentiate(Z, M, Z);
		}

		// The rest of Appendix B.3.1 with rounds iterations once the first round has exponentiated: steps 4.4 to 4.6 of that round, then the others in full.
		internal bool Finish(int rounds)
		{
			if (!Round())
			{
				return false;
			}

			for (int i = 1; i < rounds; ++i)
			{
				SampleBase();
				Exponentiate();

				if (!Round())
				{
					return false;
				}
			}

			// Step 5.
			return true;
		}

		public void Dispose()
		{
			CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_data.AsSpan()));
			_a = 0;
			Context.Dispose();
		}

		// Steps 4.4 to 4.6 for an odd w of bits bits, whose top two bits are set, and z = b^m. A prime runs every step of every round: the loop of step 4.5 goes on to bits − 1 squarings, masking off those past a, which would reveal a, the number of trailing zeros of w − 1; only a composite stops early.
		private bool Round()
		{
			Span<ulong> z = Z;
			ReadOnlySpan<ulong> one = One;
			ReadOnlySpan<ulong> minusOne = MinusOne;
			Span<ulong> scratch = Scratch;
			int a = _a;
			// Step 4.4: z = 1 or z = w − 1 makes the base no witness. z stays reduced below w, which squares take as well.
			Context.Reduce(z);
			ulong possiblyPrime = Limbs.Equal(z, one) | Limbs.Equal(z, minusOne);

			// Step 4.5.
			for (int j = 1; j < _bits; ++j)
			{
				// j = a ends the loop of the standard, and a base that has not shown w − 1 by then is a witness.
				if ((LimbArithmetic.ZeroMask((ulong)(j ^ a)) & ~possiblyPrime) is not 0)
				{
					return false;
				}

				// Step 4.5.1.
				Context.Square(z, z, scratch);
				Context.Reduce(z);
				// Step 4.5.2.
				possiblyPrime |= Limbs.Equal(z, minusOne);

				// Step 4.5.3: 1 without −1 just before it is a square root of 1 that a prime does not have.
				if ((Limbs.Equal(z, one) & ~possiblyPrime) is not 0)
				{
					return false;
				}
			}

			// Step 4.6.
			return possiblyPrime is not 0;
		}
	}
}
