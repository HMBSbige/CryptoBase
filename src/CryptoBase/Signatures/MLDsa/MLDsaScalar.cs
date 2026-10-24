namespace CryptoBase.Signatures.MLDsa;

internal readonly struct MLDsaScalar : IMLDsaKernel
{
	private const int N = MLDsaConstants.N;
	private const int Q = MLDsaConstants.Q;
	private const int D = MLDsaConstants.D;

	public static bool IsSupported => true;

	// Each of the eight layers adds less than q to a coefficient, so they stay below 9q. The butterflies of the first three layers (len = 128, 64, 32) keep within each f[j + 32i] for i < 8, and those of the last three within each group of len = 4, which has m = 32 to 63 and starts at 8(m − 32); both take their three layers in registers, and the two layers between take the loop of Algorithm 41.
	public static void Ntt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		ref int zetas = ref MemoryMarshal.GetReference(MLDsaConstants.Zetas);

		for (nint j = 0; j < 32; ++j)
		{
			NttThreeLayers(ref Unsafe.Add(ref coefficients, j), 32, ref zetas, 1);
		}

		nint k = 8;

		for (nint length = 16; length >= 8; length >>= 1)
		{
			for (nint start = 0; start < N; start += 2 * length)
			{
				long zeta = Unsafe.Add(ref zetas, k++);
				ref int low = ref Unsafe.Add(ref coefficients, start);
				ref int high = ref Unsafe.Add(ref low, length);

				for (nint j = 0; j < length; ++j)
				{
					int t = MontgomeryReduce(zeta * Unsafe.Add(ref high, j));
					int x = Unsafe.Add(ref low, j);
					Unsafe.Add(ref high, j) = x - t;
					Unsafe.Add(ref low, j) = x + t;
				}
			}
		}

		for (nint m = 32; m < 64; ++m)
		{
			NttThreeLayers(ref Unsafe.Add(ref coefficients, 8 * (m - 32)), 1, ref zetas, m);
		}
	}

	// The sums double in each layer, so coefficient 0 reaches 256 times the input bound, below 2^31 for inputs below q. The layers go as in Ntt in reverse, a group of len = 4 with m of Algorithm 42 starting at 8(63 − m), and the last three also multiply by InverseNttFactor, which ends Algorithm 42.
	public static void InverseNtt(Span<int> f)
	{
		Debug.Assert(f.Length is N);

		ref int coefficients = ref MemoryMarshal.GetReference(f);
		ref int zetas = ref MemoryMarshal.GetReference(MLDsaConstants.Zetas);

		for (nint m = 63; m >= 32; --m)
		{
			InverseNttThreeLayers(ref Unsafe.Add(ref coefficients, 8 * (63 - m)), 1, ref zetas, m, false);
		}

		nint k = 32;

		for (nint length = 8; length <= 16; length <<= 1)
		{
			for (nint start = 0; start < N; start += 2 * length)
			{
				long zeta = -Unsafe.Add(ref zetas, --k);
				ref int low = ref Unsafe.Add(ref coefficients, start);
				ref int high = ref Unsafe.Add(ref low, length);

				for (nint j = 0; j < length; ++j)
				{
					int x = Unsafe.Add(ref low, j);
					int y = Unsafe.Add(ref high, j);
					Unsafe.Add(ref low, j) = x + y;
					Unsafe.Add(ref high, j) = MontgomeryReduce(zeta * (x - y));
				}
			}
		}

		for (nint j = 0; j < 32; ++j)
		{
			InverseNttThreeLayers(ref Unsafe.Add(ref coefficients, j), 32, ref zetas, 1, true);
		}
	}

	// A product is below 9q², so the sum of eight stays below 2^31 · q, the input bound of MontgomeryReduce.
	public static void MultiplyAccumulate(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> destination, int count)
	{
		Debug.Assert(count is >= 1 and <= 8);
		Debug.Assert(a.Length >= count * N && b.Length >= count * N && destination.Length is N);

		ref int x = ref MemoryMarshal.GetReference(a);
		ref int y = ref MemoryMarshal.GetReference(b);
		ref int z = ref MemoryMarshal.GetReference(destination);

		for (nint i = 0; i < N; ++i)
		{
			long sum = 0;

			for (nint j = 0; j < count; ++j)
			{
				sum += (long)Unsafe.Add(ref x, j * N + i) * Unsafe.Add(ref y, j * N + i);
			}

			Unsafe.Add(ref z, i) = MontgomeryReduce(sum);
		}
	}

	public static void Reduce(Span<int> f)
	{
		for (int i = 0; i < f.Length; ++i)
		{
			f[i] = Reduce32(f[i]);
		}
	}

	public static void Add(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N);

		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = left[i] + right[i];
		}
	}

	// bound − 1 − |f_i| is negative exactly where the bound is reached; the sign of f_i must not leak.
	public static bool ExceedsBound(ReadOnlySpan<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		int exceeded = 0;

		for (int i = 0; i < f.Length; ++i)
		{
			int sign = f[i] >> 31;
			exceeded |= bound - 1 - ((f[i] ^ sign) - sign);
		}

		return exceeded < 0;
	}

	public static bool AddReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		int exceeded = 0;

		for (int i = 0; i < destination.Length; ++i)
		{
			int value = Reduce32(left[i] + right[i]);
			destination[i] = value;
			int sign = value >> 31;
			exceeded |= bound - 1 - ((value ^ sign) - sign);
		}

		return exceeded < 0;
	}

	public static bool SubtractReduceExceedsBound(ReadOnlySpan<int> left, ReadOnlySpan<int> right, Span<int> destination, int bound)
	{
		Debug.Assert(left.Length is N && right.Length is N && destination.Length is N && bound is > 0 and <= 2097409);

		int exceeded = 0;

		for (int i = 0; i < destination.Length; ++i)
		{
			int value = Reduce32(left[i] - right[i]);
			destination[i] = value;
			int sign = value >> 31;
			exceeded |= bound - 1 - ((value ^ sign) - sign);
		}

		return exceeded < 0;
	}

	public static bool ReduceExceedsBound(Span<int> f, int bound)
	{
		Debug.Assert(f.Length is N && bound is > 0 and <= 2097409);

		int exceeded = 0;

		for (int i = 0; i < f.Length; ++i)
		{
			int value = Reduce32(f[i]);
			f[i] = value;
			int sign = value >> 31;
			exceeded |= bound - 1 - ((value ^ sign) - sign);
		}

		return exceeded < 0;
	}

	public static void Power2Round(ReadOnlySpan<int> t, Span<int> high, Span<int> low)
	{
		Debug.Assert(t.Length is N && high.Length is N && low.Length is N);

		for (int i = 0; i < t.Length; ++i)
		{
			int r = ToCanonical(Reduce32(t[i]));
			int r1 = r + (1 << D - 1) - 1 >> D;
			high[i] = r1;
			low[i] = r - (r1 << D);
		}
	}

	public static void Decompose(ReadOnlySpan<int> r, Span<int> high, Span<int> low, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);
		Debug.Assert(r.Length is N && high.Length is N && low.Length is N);

		for (int i = 0; i < r.Length; ++i)
		{
			high[i] = Decompose(r[i], gamma2, out int r0);
			low[i] = r0;
		}
	}

	// high · 2γ2 + low has other HighBits than high where low is outside [−γ2, γ2], or is −γ2 and high is not 0, which line 4 of Algorithm 36 would leave as 0: where γ2 − low or low + γ2 − [high ≠ 0] is negative. The sign bits are taken in 64 bits, which no int32 low overflows, so that no comparison of the values can become a branch.
	public static int MakeHint(ReadOnlySpan<int> low, ReadOnlySpan<int> high, Span<int> hint, int gamma2)
	{
		Debug.Assert(low.Length is N && high.Length is N && hint.Length is N);

		int count = 0;

		for (int i = 0; i < low.Length; ++i)
		{
			long a0 = low[i];
			long nonzero = (uint)-high[i] >> 31;
			int h = (int)((ulong)(gamma2 - a0 | a0 + gamma2 - nonzero) >> 63);
			hint[i] = h;
			count += h;
		}

		return count;
	}

	// Verification handles public data, so the hints may steer branches.
	public static void UseHint(ReadOnlySpan<int> r, ReadOnlySpan<int> hint, Span<int> destination, int gamma2)
	{
		Debug.Assert(r.Length is N && hint.Length is N && destination.Length is N);

		int m = (Q - 1) / (2 * gamma2);

		for (int i = 0; i < r.Length; ++i)
		{
			int r1 = Decompose(r[i], gamma2, out int r0);

			if (hint[i] is not 0)
			{
				r1 = r0 > 0 ? r1 + 1 : r1 - 1 + m;
				r1 = r1 >= m ? r1 - m : r1;
			}

			destination[i] = r1;
		}
	}

	// CoeffFromThreeBytes (Algorithm 14) clears the top bit of the third byte.
	public static int RejectSample(ReadOnlySpan<byte> source, Span<int> destination)
	{
		Debug.Assert(source.Length % 3 is 0);

		int count = 0;

		for (int i = 0; (uint)i < (uint)source.Length && count < destination.Length; i += 3)
		{
			int value = source[i] | source[i + 1] << 8 | (source[i + 2] & 0x7F) << 16;

			if (value < Q)
			{
				destination[count++] = value;
			}
		}

		return count;
	}

	// CoeffFromHalfByte (Algorithm 15) for the low then the high half of each byte. Every candidate is computed and written, and the count advances by whether it is accepted, so that the values do not steer branches.
	public static int RejectEta(ReadOnlySpan<byte> source, Span<int> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		int count = 0;

		for (int i = 0; i < source.Length && (uint)count < (uint)destination.Length; ++i)
		{
			count = AppendEta(source[i] & 15, destination, count, eta);

			if ((uint)count < (uint)destination.Length)
			{
				count = AppendEta(source[i] >> 4, destination, count, eta);
			}
		}

		return count;
	}

	public static void EncodeT1(ReadOnlySpan<int> t1, Span<byte> destination)
	{
		Pack(t1, destination, 10, 0, false);
	}

	public static void DecodeT1(ReadOnlySpan<byte> source, Span<int> f)
	{
		Unpack(source, f, 10);

		for (int i = 0; i < f.Length; ++i)
		{
			f[i] <<= D;
		}
	}

	public static void EncodeT0(ReadOnlySpan<int> t0, Span<byte> destination)
	{
		Pack(t0, destination, D, 1 << D - 1, true);
	}

	public static void EncodeEta(ReadOnlySpan<int> s, Span<byte> destination, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		Pack(s, destination, eta is 2 ? 3 : 4, eta, true);
	}

	// Stays non-negative while every packed value is at most 2η, so that the check takes no branch on the values.
	public static bool DecodeEta(ReadOnlySpan<byte> source, Span<int> s, int eta)
	{
		Debug.Assert(eta is 2 or 4);

		Unpack(source, s, eta is 2 ? 3 : 4);
		int inRange = 0;

		for (int i = 0; i < s.Length; ++i)
		{
			inRange |= 2 * eta - s[i];
			s[i] = eta - s[i];
		}

		return inRange >= 0;
	}

	public static void EncodeZ(ReadOnlySpan<int> z, Span<byte> destination, int gamma1Bits)
	{
		Debug.Assert(gamma1Bits is 17 or 19);

		Pack(z, destination, gamma1Bits + 1, 1 << gamma1Bits, true);
	}

	public static void DecodeZ(ReadOnlySpan<byte> source, Span<int> z, int gamma1Bits)
	{
		Debug.Assert(gamma1Bits is 17 or 19);

		Unpack(source, z, gamma1Bits + 1);

		for (int i = 0; i < z.Length; ++i)
		{
			z[i] = (1 << gamma1Bits) - z[i];
		}
	}

	public static void EncodeW1(ReadOnlySpan<int> w1, Span<byte> destination, int gamma2)
	{
		Debug.Assert(gamma2 is MLDsaConstants.Gamma2Small or MLDsaConstants.Gamma2Large);

		Pack(w1, destination, gamma2 is MLDsaConstants.Gamma2Small ? 6 : 4, 0, false);
	}

	// Three layers of Algorithm 41 on f[0], f[stride], ..., f[7 · stride]: the group with Zetas[m], then the two it splits into, with Zetas[2m] and Zetas[2m + 1], then the four with Zetas[4m] to Zetas[4m + 3].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NttThreeLayers(ref int f, nint stride, ref int zetas, nint m)
	{
		int f0 = f;
		int f1 = Unsafe.Add(ref f, stride);
		int f2 = Unsafe.Add(ref f, 2 * stride);
		int f3 = Unsafe.Add(ref f, 3 * stride);
		int f4 = Unsafe.Add(ref f, 4 * stride);
		int f5 = Unsafe.Add(ref f, 5 * stride);
		int f6 = Unsafe.Add(ref f, 6 * stride);
		int f7 = Unsafe.Add(ref f, 7 * stride);

		long zeta = Unsafe.Add(ref zetas, m);
		Butterfly(ref f0, ref f4, zeta);
		Butterfly(ref f1, ref f5, zeta);
		Butterfly(ref f2, ref f6, zeta);
		Butterfly(ref f3, ref f7, zeta);

		zeta = Unsafe.Add(ref zetas, 2 * m);
		Butterfly(ref f0, ref f2, zeta);
		Butterfly(ref f1, ref f3, zeta);
		zeta = Unsafe.Add(ref zetas, 2 * m + 1);
		Butterfly(ref f4, ref f6, zeta);
		Butterfly(ref f5, ref f7, zeta);

		Butterfly(ref f0, ref f1, Unsafe.Add(ref zetas, 4 * m));
		Butterfly(ref f2, ref f3, Unsafe.Add(ref zetas, 4 * m + 1));
		Butterfly(ref f4, ref f5, Unsafe.Add(ref zetas, 4 * m + 2));
		Butterfly(ref f6, ref f7, Unsafe.Add(ref zetas, 4 * m + 3));

		f = f0;
		Unsafe.Add(ref f, stride) = f1;
		Unsafe.Add(ref f, 2 * stride) = f2;
		Unsafe.Add(ref f, 3 * stride) = f3;
		Unsafe.Add(ref f, 4 * stride) = f4;
		Unsafe.Add(ref f, 5 * stride) = f5;
		Unsafe.Add(ref f, 6 * stride) = f6;
		Unsafe.Add(ref f, 7 * stride) = f7;
	}

	// Three layers of Algorithm 42 on f[0], f[stride], ..., f[7 · stride], with its m: the four groups with Zetas[4m + 3] down to Zetas[4m], then the two they join into, with Zetas[2m + 1] and Zetas[2m], then the one with Zetas[m]; with scale, the last also multiplies by InverseNttFactor.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseNttThreeLayers(ref int f, nint stride, ref int zetas, nint m, bool scale)
	{
		int f0 = f;
		int f1 = Unsafe.Add(ref f, stride);
		int f2 = Unsafe.Add(ref f, 2 * stride);
		int f3 = Unsafe.Add(ref f, 3 * stride);
		int f4 = Unsafe.Add(ref f, 4 * stride);
		int f5 = Unsafe.Add(ref f, 5 * stride);
		int f6 = Unsafe.Add(ref f, 6 * stride);
		int f7 = Unsafe.Add(ref f, 7 * stride);

		InverseButterfly(ref f0, ref f1, -Unsafe.Add(ref zetas, 4 * m + 3));
		InverseButterfly(ref f2, ref f3, -Unsafe.Add(ref zetas, 4 * m + 2));
		InverseButterfly(ref f4, ref f5, -Unsafe.Add(ref zetas, 4 * m + 1));
		InverseButterfly(ref f6, ref f7, -Unsafe.Add(ref zetas, 4 * m));

		long zeta = -Unsafe.Add(ref zetas, 2 * m + 1);
		InverseButterfly(ref f0, ref f2, zeta);
		InverseButterfly(ref f1, ref f3, zeta);
		zeta = -Unsafe.Add(ref zetas, 2 * m);
		InverseButterfly(ref f4, ref f6, zeta);
		InverseButterfly(ref f5, ref f7, zeta);

		zeta = -Unsafe.Add(ref zetas, m);

		if (scale)
		{
			ScaledInverseButterfly(ref f0, ref f4, zeta);
			ScaledInverseButterfly(ref f1, ref f5, zeta);
			ScaledInverseButterfly(ref f2, ref f6, zeta);
			ScaledInverseButterfly(ref f3, ref f7, zeta);
		}
		else
		{
			InverseButterfly(ref f0, ref f4, zeta);
			InverseButterfly(ref f1, ref f5, zeta);
			InverseButterfly(ref f2, ref f6, zeta);
			InverseButterfly(ref f3, ref f7, zeta);
		}

		f = f0;
		Unsafe.Add(ref f, stride) = f1;
		Unsafe.Add(ref f, 2 * stride) = f2;
		Unsafe.Add(ref f, 3 * stride) = f3;
		Unsafe.Add(ref f, 4 * stride) = f4;
		Unsafe.Add(ref f, 5 * stride) = f5;
		Unsafe.Add(ref f, 6 * stride) = f6;
		Unsafe.Add(ref f, 7 * stride) = f7;
	}

	// The butterfly of NTT (Algorithm 41).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Butterfly(ref int low, ref int high, long zeta)
	{
		int t = MontgomeryReduce(zeta * high);
		int x = low;
		high = x - t;
		low = x + t;
	}

	// The butterfly of NTT⁻¹ (Algorithm 42), zeta being the negated Zetas[m].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseButterfly(ref int low, ref int high, long zeta)
	{
		int x = low;
		int y = high;
		low = x + y;
		high = MontgomeryReduce(zeta * (x - y));
	}

	// InverseButterfly with both results then multiplied by InverseNttFactor, the same values as the loop that ends Algorithm 42.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ScaledInverseButterfly(ref int low, ref int high, long zeta)
	{
		int x = low;
		int y = high;
		low = MontgomeryReduce((long)MLDsaConstants.InverseNttFactor * (x + y));
		high = MontgomeryReduce((long)MLDsaConstants.InverseNttFactor * MontgomeryReduce(zeta * (x - y)));
	}

	// a · R⁻¹ mod q for |a| < 2^31 · q, in (−q, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int MontgomeryReduce(long a)
	{
		int t = (int)a * MLDsaConstants.QInverse;
		return (int)(a - (long)t * Q >> 32);
	}

	// a mod q in [−6283008, 6283008] for |a| < 2^31 − 2^22, the centered representative wherever that is below 2097409 in magnitude.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int Reduce32(int a)
	{
		int t = a + (1 << 22) >> 23;
		return a - t * Q;
	}

	// Maps (−q, q) to [0, q).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ToCanonical(int a)
	{
		return a + (a >> 31 & Q);
	}

	// r1 = ⌈r / 128⌉ · M >> s is ⌊(r + γ2 − 1) / (2γ2)⌋ for r in [0, q), with M / 2^s approximating 128 / (2γ2). The last high bits, (q − 1) / (2γ2), become 0 (Algorithm 36, line 4): by the mask for γ2 = (q − 1) / 32, and by the select for (q − 1) / 88. The low bits above (q − 1) / 2 are those of r − q.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int Decompose(int r, int gamma2, out int r0)
	{
		int a = ToCanonical(r);
		int a1 = a + 127 >> 7;

		if (gamma2 is MLDsaConstants.Gamma2Large)
		{
			a1 = a1 * 1025 + (1 << 21) >> 22 & 15;
		}
		else
		{
			a1 = a1 * 11275 + (1 << 23) >> 24;
			a1 ^= 43 - a1 >> 31 & a1;
		}

		r0 = a - a1 * 2 * gamma2;
		r0 -= (Q - 1) / 2 - r0 >> 31 & Q;
		return a1;
	}

	// For η = 2, b mod 5 is b − 5 · ⌊205b / 1024⌋ for b < 15.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int AppendEta(int b, Span<int> destination, int count, int eta)
	{
		int accepted;
		int value;

		if (eta is 2)
		{
			accepted = b - 15 >>> 31;
			value = 2 - (b - (205 * b >> 10) * 5);
		}
		else
		{
			accepted = b - 9 >>> 31;
			value = 4 - b;
		}

		destination[count] = value;
		return count + accepted;
	}

	// Writes bits low bits of each value in order, least significant first: of bias − f_i for BitPack (Algorithm 17), of f_i for SimpleBitPack (Algorithm 16). 256 · bits fills whole 32-bit words, so the bit buffer is empty at the end.
	private static void Pack(ReadOnlySpan<int> f, Span<byte> destination, int bits, int bias, bool subtract)
	{
		Debug.Assert(f.Length is N && destination.Length >= 32 * bits);

		ulong mask = (1UL << bits) - 1;
		ulong buffer = 0;
		int buffered = 0;
		int offset = 0;

		for (int i = 0; i < N; ++i)
		{
			int value = subtract ? bias - f[i] : f[i];
			buffer |= ((uint)value & mask) << buffered;
			buffered += bits;

			if (buffered >= 32)
			{
				BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset), (uint)buffer);
				buffer >>= 32;
				buffered -= 32;
				offset += sizeof(uint);
			}
		}
	}

	// The inverse of Pack without the bias: each run of bits bits, least significant first. Reads exactly 32 · bits bytes.
	private static void Unpack(ReadOnlySpan<byte> source, Span<int> f, int bits)
	{
		Debug.Assert(source.Length >= 32 * bits && f.Length is N);

		uint mask = (1u << bits) - 1;
		ulong buffer = 0;
		int buffered = 0;
		int offset = 0;

		for (int i = 0; i < N; ++i)
		{
			if (buffered < bits)
			{
				buffer |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(offset)) << buffered;
				buffered += 32;
				offset += sizeof(uint);
			}

			f[i] = (int)((uint)buffer & mask);
			buffer >>= bits;
			buffered -= bits;
		}
	}
}
