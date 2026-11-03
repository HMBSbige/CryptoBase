namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Trial division of the candidates of ProbablePrime by the odd primes below Bound, one prime per lane of the widest vectors of the platform. The remainder by a prime p is that of Σ h_j·w_j over the 32-bit halves h_j of the candidate, with w_j = 2^(32j) mod p: each term is below 2^45 and a sum of up to 256 terms, for candidates of 8192 bits, below 2^53, so that the sums are exact in doubles and the halves broadcast to every lane.
// The quotient ⌊s·(1/p)⌋ in doubles, with 1/p rounded, may be one off either way, which one correction in each direction undoes; nothing divides or branches on a sum. The lanes past the primes divide by 2 the lowest half alone, which an odd candidate leaves at 1.
internal sealed class TrialDivision
{
	// Appendix B.3 of FIPS 186-5 suggests a bound from 10^3 to 10^5; 2^13 keeps the sums exact for every candidate.
	internal const int Bound = 8192;

	// Lanes per block of HasSmallFactor: four vectors of eight.
	private const int Block = 32;

	private static readonly double[] Primes = GetPrimes();
	private static readonly double[] Inverses = [.. Primes.Select(static p => 1 / p)];

	// The weights of the most halves taken last, which serve any fewer, while they live: they are public and the same for every candidate.
	private static readonly WeakReference<double[]> LastWeights = new([]);

	private readonly double[] _weights;
	private readonly int _halves;

	// For candidates of limbs limbs.
	internal TrialDivision(int limbs)
	{
		_halves = 2 * limbs;
		_weights = GetWeights(_halves);
	}

	// w_j of every lane in row j, for halves halves or more.
	private static double[] GetWeights(int halves)
	{
		int lanes = Primes.Length;

		if (LastWeights.TryGetTarget(out double[]? last) && last.Length >= halves * lanes)
		{
			return last;
		}

		double[] weights = new double[halves * lanes];

		for (int i = 0; i < lanes; ++i)
		{
			ulong prime = (ulong)Primes[i];
			ulong weight = 1;

			for (int j = 0; j < halves; ++j)
			{
				weights[j * lanes + i] = prime is 2 && j is not 0 ? 0 : weight;
				weight = (weight << 32) % prime;
			}
		}

		LastWeights.SetTarget(weights);
		return weights;
	}

	// Whether an odd candidate of the limbs of the constructor has an odd prime factor below Bound, in a time that only depends on its length if it has none.
	internal bool HasSmallFactor(ReadOnlySpan<ulong> value)
	{
		Debug.Assert(value.Length * 2 == _halves && (value[0] & 1) is 1);

		Span<double> halves = stackalloc double[_halves];

		for (int j = 0; j < _halves; ++j)
		{
			halves[j] = (uint)(value[j / 2] >> 32 * (j & 1));
		}

		bool found = Vector512.IsHardwareAccelerated ? HasSmallFactor<Lanes512>(halves) : Vector256.IsHardwareAccelerated ? HasSmallFactor<Lanes256>(halves) : Vector128.IsHardwareAccelerated ? HasSmallFactor<Lanes128>(halves) : HasSmallFactor<Lanes64>(halves);
		halves.Clear();
		return found;
	}

	private bool HasSmallFactor<TLanes>(ReadOnlySpan<double> halves) where TLanes : struct, ITrialLanes<TLanes>
	{
		int lanes = Primes.Length;
		int count = TLanes.Count;
		ref double weights = ref MemoryMarshal.GetArrayDataReference(_weights);
		ref double primes = ref MemoryMarshal.GetArrayDataReference(Primes);
		ref double inverses = ref MemoryMarshal.GetArrayDataReference(Inverses);

		for (int block = 0; block < lanes; block += 4 * count)
		{
			TLanes s0 = default;
			TLanes s1 = default;
			TLanes s2 = default;
			TLanes s3 = default;
			ref double row = ref Unsafe.Add(ref weights, block);

			foreach (double half in halves)
			{
				TLanes h = TLanes.Create(half);
				s0 = TLanes.MultiplyAdd(h, TLanes.Load(ref row, 0), s0);
				s1 = TLanes.MultiplyAdd(h, TLanes.Load(ref row, count), s1);
				s2 = TLanes.MultiplyAdd(h, TLanes.Load(ref row, 2 * count), s2);
				s3 = TLanes.MultiplyAdd(h, TLanes.Load(ref row, 3 * count), s3);
				row = ref Unsafe.Add(ref row, lanes);
			}

			ref double p = ref Unsafe.Add(ref primes, block);
			ref double q = ref Unsafe.Add(ref inverses, block);

			if (TLanes.AnyDivides(s0, ref p, ref q) | TLanes.AnyDivides(s1, ref Unsafe.Add(ref p, count), ref Unsafe.Add(ref q, count)) | TLanes.AnyDivides(s2, ref Unsafe.Add(ref p, 2 * count), ref Unsafe.Add(ref q, 2 * count)) | TLanes.AnyDivides(s3, ref Unsafe.Add(ref p, 3 * count), ref Unsafe.Add(ref q, 3 * count)))
			{
				return true;
			}
		}

		return false;
	}

	// The odd primes below Bound, then twos up to a whole number of blocks.
	private static double[] GetPrimes()
	{
		bool[] composite = new bool[Bound];
		List<double> primes = [];

		for (int i = 3; i < Bound; i += 2)
		{
			if (composite[i])
			{
				continue;
			}

			primes.Add(i);

			for (int j = i * i; j < Bound; j += 2 * i)
			{
				composite[j] = true;
			}
		}

		while (primes.Count % Block is not 0)
		{
			primes.Add(2);
		}

		return [.. primes];
	}

	// Sums of products in the lanes of a vector of doubles, one prime per lane.
	private interface ITrialLanes<TSelf> where TSelf : struct, ITrialLanes<TSelf>
	{
		static abstract int Count { get; }

		static abstract TSelf Create(double value);

		static abstract TSelf Load(ref double source, int offset);

		static abstract TSelf MultiplyAdd(TSelf left, TSelf right, TSelf addend);

		// Whether some lane of sums is a multiple of the prime of that lane at primes, whose inverse is at inverses.
		static abstract bool AnyDivides(TSelf sums, ref double primes, ref double inverses);
	}

	private readonly struct Lanes512(Vector512<double> value) : ITrialLanes<Lanes512>
	{
		private readonly Vector512<double> _value = value;

		public static int Count => Vector512<double>.Count;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes512 Create(double value)
		{
			return new Lanes512(Vector512.Create(value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes512 Load(ref double source, int offset)
		{
			return new Lanes512(Vector512.LoadUnsafe(ref source, (nuint)offset));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes512 MultiplyAdd(Lanes512 left, Lanes512 right, Lanes512 addend)
		{
			return new Lanes512(Vector512.FusedMultiplyAdd(left._value, right._value, addend._value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool AnyDivides(Lanes512 sums, ref double primes, ref double inverses)
		{
			Vector512<double> p = Vector512.LoadUnsafe(ref primes);
			Vector512<double> r = Vector512.FusedMultiplyAdd(-Vector512.Floor(sums._value * Vector512.LoadUnsafe(ref inverses)), p, sums._value);
			r += p & Vector512.LessThan(r, Vector512<double>.Zero);
			r -= p & Vector512.GreaterThanOrEqual(r, p);
			return Vector512.EqualsAny(r, Vector512<double>.Zero);
		}
	}

	private readonly struct Lanes256(Vector256<double> value) : ITrialLanes<Lanes256>
	{
		private readonly Vector256<double> _value = value;

		public static int Count => Vector256<double>.Count;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes256 Create(double value)
		{
			return new Lanes256(Vector256.Create(value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes256 Load(ref double source, int offset)
		{
			return new Lanes256(Vector256.LoadUnsafe(ref source, (nuint)offset));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes256 MultiplyAdd(Lanes256 left, Lanes256 right, Lanes256 addend)
		{
			return new Lanes256(Vector256.FusedMultiplyAdd(left._value, right._value, addend._value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool AnyDivides(Lanes256 sums, ref double primes, ref double inverses)
		{
			Vector256<double> p = Vector256.LoadUnsafe(ref primes);
			Vector256<double> r = Vector256.FusedMultiplyAdd(-Vector256.Floor(sums._value * Vector256.LoadUnsafe(ref inverses)), p, sums._value);
			r += p & Vector256.LessThan(r, Vector256<double>.Zero);
			r -= p & Vector256.GreaterThanOrEqual(r, p);
			return Vector256.EqualsAny(r, Vector256<double>.Zero);
		}
	}

	private readonly struct Lanes128(Vector128<double> value) : ITrialLanes<Lanes128>
	{
		private readonly Vector128<double> _value = value;

		public static int Count => Vector128<double>.Count;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes128 Create(double value)
		{
			return new Lanes128(Vector128.Create(value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes128 Load(ref double source, int offset)
		{
			return new Lanes128(Vector128.LoadUnsafe(ref source, (nuint)offset));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Lanes128 MultiplyAdd(Lanes128 left, Lanes128 right, Lanes128 addend)
		{
			return new Lanes128(Vector128.FusedMultiplyAdd(left._value, right._value, addend._value));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool AnyDivides(Lanes128 sums, ref double primes, ref double inverses)
		{
			Vector128<double> p = Vector128.LoadUnsafe(ref primes);
			Vector128<double> r = Vector128.FusedMultiplyAdd(-Vector128.Floor(sums._value * Vector128.LoadUnsafe(ref inverses)), p, sums._value);
			r += p & Vector128.LessThan(r, Vector128<double>.Zero);
			r -= p & Vector128.GreaterThanOrEqual(r, p);
			return Vector128.EqualsAny(r, Vector128<double>.Zero);
		}
	}

	// One lane, without vectors.
	private readonly struct Lanes64(double value) : ITrialLanes<Lanes64>
	{
		private readonly double _value = value;

		public static int Count => 1;

		public static Lanes64 Create(double value)
		{
			return new Lanes64(value);
		}

		public static Lanes64 Load(ref double source, int offset)
		{
			return new Lanes64(Unsafe.Add(ref source, offset));
		}

		public static Lanes64 MultiplyAdd(Lanes64 left, Lanes64 right, Lanes64 addend)
		{
			return new Lanes64(left._value * right._value + addend._value);
		}

		public static bool AnyDivides(Lanes64 sums, ref double primes, ref double inverses)
		{
			long prime = (long)primes;
			long remainder = (long)sums._value - (long)(sums._value * inverses) * prime;
			remainder += prime & remainder >> 63;
			remainder -= prime & ~(remainder - prime >> 63);
			return remainder is 0;
		}
	}
}
