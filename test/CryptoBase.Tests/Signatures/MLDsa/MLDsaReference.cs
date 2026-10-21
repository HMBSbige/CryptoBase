namespace CryptoBase.Tests.Signatures.MLDsa;

// FIPS 204 step by step over plain integers modulo q, for differential tests of the kernels.
internal static class MLDsaReference
{
	public const int N = 256;
	public const int Q = 8380417;
	public const int D = 13;
	public const long R = 1L << 32;

	public static int Mod(long value)
	{
		long remainder = value % Q;
		return (int)(remainder < 0 ? remainder + Q : remainder);
	}

	// m mod± α, in (−⌈α/2⌉, ⌊α/2⌋] (Sec. 2.3).
	public static int ModPlusMinus(long value, int alpha)
	{
		long remainder = value % alpha;

		if (remainder < 0)
		{
			remainder += alpha;
		}

		return (int)(remainder > alpha / 2 ? remainder - alpha : remainder);
	}

	public static int Power(int value, int exponent)
	{
		long result = 1;

		for (int i = 0; i < exponent; ++i)
		{
			result = result * value % Q;
		}

		return (int)result;
	}

	public static int BitReverse8(int value)
	{
		int result = 0;

		for (int i = 0; i < 8; ++i)
		{
			result |= (value >> i & 1) << 7 - i;
		}

		return result;
	}

	// ζ^BitRev8(k) mod q with ζ = 1753 (Sec. 7.5).
	public static int Zeta(int k)
	{
		return Power(1753, BitReverse8(k));
	}

	// Algorithm 41.
	public static int[] Ntt(ReadOnlySpan<int> w)
	{
		int[] wHat = new int[N];

		for (int j = 0; j < N; ++j)
		{
			wHat[j] = Mod(w[j]);
		}

		int m = 0;

		for (int length = 128; length >= 1; length /= 2)
		{
			for (int start = 0; start < N; start += 2 * length)
			{
				long z = Zeta(++m);

				for (int j = start; j < start + length; ++j)
				{
					int t = Mod(z * wHat[j + length]);
					wHat[j + length] = Mod(wHat[j] - t);
					wHat[j] = Mod(wHat[j] + t);
				}
			}
		}

		return wHat;
	}

	// Algorithm 42.
	public static int[] InverseNtt(ReadOnlySpan<int> wHat)
	{
		int[] w = new int[N];

		for (int j = 0; j < N; ++j)
		{
			w[j] = Mod(wHat[j]);
		}

		int m = 256;

		for (int length = 1; length < N; length *= 2)
		{
			for (int start = 0; start < N; start += 2 * length)
			{
				long z = -Zeta(--m);

				for (int j = start; j < start + length; ++j)
				{
					int t = w[j];
					w[j] = Mod(t + w[j + length]);
					w[j + length] = Mod(t - w[j + length]);
					w[j + length] = Mod(z * w[j + length]);
				}
			}
		}

		const long f = 8347681;

		for (int j = 0; j < N; ++j)
		{
			w[j] = Mod(f * w[j]);
		}

		return w;
	}

	// Algorithm 45.
	public static int[] MultiplyNtt(ReadOnlySpan<int> aHat, ReadOnlySpan<int> bHat)
	{
		int[] cHat = new int[N];

		for (int i = 0; i < N; ++i)
		{
			cHat[i] = Mod((long)aHat[i] * bHat[i]);
		}

		return cHat;
	}

	// Algorithm 44.
	public static int[] AddNtt(ReadOnlySpan<int> aHat, ReadOnlySpan<int> bHat)
	{
		int[] cHat = new int[N];

		for (int i = 0; i < N; ++i)
		{
			cHat[i] = Mod((long)aHat[i] + bHat[i]);
		}

		return cHat;
	}

	// The product in Z_q[X] / (X^256 + 1), term by term.
	public static int[] MultiplyPolynomials(ReadOnlySpan<int> f, ReadOnlySpan<int> g)
	{
		long[] product = new long[N];

		for (int i = 0; i < N; ++i)
		{
			for (int j = 0; j < N; ++j)
			{
				long term = (long)Mod(f[i]) * Mod(g[j]) % Q;

				if (i + j < N)
				{
					product[i + j] += term;
				}
				else
				{
					product[i + j - N] -= term;
				}
			}
		}

		return product.Select(Mod).ToArray();
	}

	// Algorithm 35.
	public static (int R1, int R0) Power2Round(long r)
	{
		int rPlus = Mod(r);
		int r0 = ModPlusMinus(rPlus, 1 << D);
		return ((rPlus - r0) / (1 << D), r0);
	}

	// Algorithm 36.
	public static (int R1, int R0) Decompose(long r, int gamma2)
	{
		int rPlus = Mod(r);
		int r0 = ModPlusMinus(rPlus, 2 * gamma2);

		if (rPlus - r0 == Q - 1)
		{
			return (0, r0 - 1);
		}

		return ((rPlus - r0) / (2 * gamma2), r0);
	}

	// Algorithm 37.
	public static int HighBits(long r, int gamma2)
	{
		return Decompose(r, gamma2).R1;
	}

	// Algorithm 38.
	public static int LowBits(long r, int gamma2)
	{
		return Decompose(r, gamma2).R0;
	}

	// Algorithm 39.
	public static int MakeHint(long z, long r, int gamma2)
	{
		int r1 = HighBits(r, gamma2);
		int v1 = HighBits(r + z, gamma2);
		return r1 != v1 ? 1 : 0;
	}

	// Algorithm 40.
	public static int UseHint(int h, long r, int gamma2)
	{
		int m = (Q - 1) / (2 * gamma2);
		(int r1, int r0) = Decompose(r, gamma2);

		if (h is 1 && r0 > 0)
		{
			return (r1 + 1) % m;
		}

		if (h is 1 && r0 <= 0)
		{
			return (r1 - 1 + m) % m;
		}

		return r1;
	}

	// Algorithm 16.
	public static byte[] SimpleBitPack(ReadOnlySpan<int> w, int b)
	{
		int bits = BitLength(b);
		List<int> z = [];

		for (int i = 0; i < N; ++i)
		{
			if (w[i] < 0 || w[i] > b)
			{
				throw new ArgumentOutOfRangeException(nameof(w), w[i], $"Coefficient {i} is outside [0, {b}].");
			}

			z.AddRange(IntegerToBits(w[i], bits));
		}

		return BitsToBytes(z);
	}

	// Algorithm 17.
	public static byte[] BitPack(ReadOnlySpan<int> w, int a, int b)
	{
		int bits = BitLength(a + b);
		List<int> z = [];

		for (int i = 0; i < N; ++i)
		{
			if (w[i] < -a || w[i] > b)
			{
				throw new ArgumentOutOfRangeException(nameof(w), w[i], $"Coefficient {i} is outside [{-a}, {b}].");
			}

			z.AddRange(IntegerToBits(b - w[i], bits));
		}

		return BitsToBytes(z);
	}

	// Algorithm 18.
	public static int[] SimpleBitUnpack(ReadOnlySpan<byte> v, int b)
	{
		int bits = BitLength(b);
		int[] z = BytesToBits(v);
		int[] w = new int[N];

		for (int i = 0; i < N; ++i)
		{
			w[i] = BitsToInteger(z.AsSpan(i * bits, bits));
		}

		return w;
	}

	// Algorithm 19.
	public static int[] BitUnpack(ReadOnlySpan<byte> v, int a, int b)
	{
		int bits = BitLength(a + b);
		int[] z = BytesToBits(v);
		int[] w = new int[N];

		for (int i = 0; i < N; ++i)
		{
			w[i] = b - BitsToInteger(z.AsSpan(i * bits, bits));
		}

		return w;
	}

	// Algorithm 14.
	public static int? CoeffFromThreeBytes(byte b0, byte b1, byte b2)
	{
		int b2Prime = b2;

		if (b2Prime > 127)
		{
			b2Prime -= 128;
		}

		int z = 65536 * b2Prime + 256 * b1 + b0;
		return z < Q ? z : null;
	}

	// Algorithm 15.
	public static int? CoeffFromHalfByte(int b, int eta)
	{
		if (eta is 2 && b < 15)
		{
			return 2 - b % 5;
		}

		if (eta is 4 && b < 9)
		{
			return 4 - b;
		}

		return null;
	}

	// Lines 4 to 11 of Algorithm 30 over a fixed input, stopping when the capacity is reached.
	public static List<int> RejectSample(ReadOnlySpan<byte> source, int capacity)
	{
		List<int> a = [];

		for (int i = 0; i + 3 <= source.Length && a.Count < capacity; i += 3)
		{
			if (CoeffFromThreeBytes(source[i], source[i + 1], source[i + 2]) is { } coefficient)
			{
				a.Add(coefficient);
			}
		}

		return a;
	}

	// Lines 4 to 15 of Algorithm 31 over a fixed input, stopping when the capacity is reached.
	public static List<int> RejectEta(ReadOnlySpan<byte> source, int capacity, int eta)
	{
		List<int> a = [];

		for (int i = 0; i < source.Length && a.Count < capacity; ++i)
		{
			int z = source[i];
			int? z0 = CoeffFromHalfByte(z % 16, eta);
			int? z1 = CoeffFromHalfByte(z / 16, eta);

			if (z0 is { } first)
			{
				a.Add(first);
			}

			if (z1 is { } second && a.Count < capacity)
			{
				a.Add(second);
			}
		}

		return a;
	}

	public static int BitLength(int value)
	{
		int bits = 0;

		for (; value > 0; value >>= 1)
		{
			++bits;
		}

		return bits;
	}

	// Algorithm 9.
	private static int[] IntegerToBits(int x, int alpha)
	{
		int[] y = new int[alpha];

		for (int i = 0; i < alpha; ++i)
		{
			y[i] = x % 2;
			x /= 2;
		}

		return y;
	}

	// Algorithm 10.
	private static int BitsToInteger(ReadOnlySpan<int> y)
	{
		int x = 0;

		for (int i = 1; i <= y.Length; ++i)
		{
			x = 2 * x + y[^i];
		}

		return x;
	}

	// Algorithm 12.
	private static byte[] BitsToBytes(List<int> y)
	{
		byte[] z = new byte[(y.Count + 7) / 8];

		for (int i = 0; i < y.Count; ++i)
		{
			z[i / 8] += (byte)(y[i] << i % 8);
		}

		return z;
	}

	// Algorithm 13.
	private static int[] BytesToBits(ReadOnlySpan<byte> z)
	{
		int[] y = new int[8 * z.Length];

		for (int i = 0; i < z.Length; ++i)
		{
			int value = z[i];

			for (int j = 0; j < 8; ++j)
			{
				y[8 * i + j] = value % 2;
				value /= 2;
			}
		}

		return y;
	}
}
