using CryptoBase.Tests.Hashes.Sha3;

namespace CryptoBase.Tests.Kems.MLKem;

// FIPS 203 step by step over plain integers modulo q, for differential tests of the kernels.
internal static class MLKemReference
{
	public const int N = 256;
	public const int Q = 3329;
	public const int R = 1 << 16;

	public static int Mod(long value)
	{
		long remainder = value % Q;
		return (int)(remainder < 0 ? remainder + Q : remainder);
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

	public static int BitReverse7(int value)
	{
		int result = 0;

		for (int i = 0; i < 7; ++i)
		{
			result |= (value >> i & 1) << 6 - i;
		}

		return result;
	}

	public static int Zeta(int i)
	{
		return Power(17, BitReverse7(i));
	}

	// Algorithm 9.
	public static int[] Ntt(ReadOnlySpan<int> f)
	{
		int[] result = new int[N];

		for (int i = 0; i < N; ++i)
		{
			result[i] = Mod(f[i]);
		}

		int k = 1;

		for (int length = 128; length >= 2; length /= 2)
		{
			for (int start = 0; start < N; start += 2 * length)
			{
				int zeta = Zeta(k++);

				for (int j = start; j < start + length; ++j)
				{
					int t = Mod((long)zeta * result[j + length]);
					result[j + length] = Mod(result[j] - t);
					result[j] = Mod(result[j] + t);
				}
			}
		}

		return result;
	}

	// Algorithm 10.
	public static int[] InverseNtt(ReadOnlySpan<int> f)
	{
		int[] result = new int[N];

		for (int i = 0; i < N; ++i)
		{
			result[i] = Mod(f[i]);
		}

		int k = 127;

		for (int length = 2; length <= 128; length *= 2)
		{
			for (int start = 0; start < N; start += 2 * length)
			{
				int zeta = Zeta(k--);

				for (int j = start; j < start + length; ++j)
				{
					int t = result[j];
					result[j] = Mod(t + result[j + length]);
					result[j + length] = Mod((long)zeta * (result[j + length] - t));
				}
			}
		}

		for (int i = 0; i < N; ++i)
		{
			result[i] = Mod(result[i] * 3303L);
		}

		return result;
	}

	// Algorithms 11 and 12.
	public static int[] MultiplyNtts(ReadOnlySpan<int> f, ReadOnlySpan<int> g)
	{
		int[] result = new int[N];

		for (int i = 0; i < N / 2; ++i)
		{
			long gamma = Power(17, 2 * BitReverse7(i) + 1);
			long a0 = f[2 * i];
			long a1 = f[2 * i + 1];
			long b0 = g[2 * i];
			long b1 = g[2 * i + 1];
			result[2 * i] = Mod(a0 * b0 + Mod(a1 * b1) * gamma);
			result[2 * i + 1] = Mod(a0 * b1 + a1 * b0);
		}

		return result;
	}

	// The product in Z_q[X] / (X^256 + 1), term by term.
	public static int[] MultiplyPolynomials(ReadOnlySpan<int> f, ReadOnlySpan<int> g)
	{
		long[] product = new long[N];

		for (int i = 0; i < N; ++i)
		{
			for (int j = 0; j < N; ++j)
			{
				long term = (long)Mod(f[i]) * Mod(g[j]);

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

	// ⌈2^d · x / q⌋ mod 2^d with the remainder deciding the rounding.
	public static int Compress(int x, int d)
	{
		long scaled = (long)Mod(x) << d;
		long quotient = scaled / Q;
		long remainder = scaled % Q;
		return (int)((quotient + (2 * remainder >= Q ? 1 : 0)) % (1 << d));
	}

	// ⌈q · y / 2^d⌋, rounding halves up.
	public static int Decompress(int y, int d)
	{
		long scaled = (long)Q * y;
		long quotient = scaled >> d;
		long remainder = scaled & (1L << d) - 1;
		return (int)(quotient + (2 * remainder >= 1L << d ? 1 : 0));
	}

	// Algorithm 5, bit by bit, for values that fit in d bits.
	public static byte[] ByteEncode(ReadOnlySpan<int> f, int d)
	{
		byte[] result = new byte[32 * d];

		for (int i = 0; i < N; ++i)
		{
			if ((uint)f[i] >= 1u << d)
			{
				throw new ArgumentOutOfRangeException(nameof(f), f[i], $"Coefficient {i} does not fit in {d} bits.");
			}

			for (int j = 0; j < d; ++j)
			{
				int bit = i * d + j;
				result[bit / 8] |= (byte)((f[i] >> j & 1) << bit % 8);
			}
		}

		return result;
	}

	// Lines 4 to 13 of Algorithm 7 over a fixed input, stopping when the capacity is reached.
	public static List<int> RejectSample(ReadOnlySpan<byte> source, int capacity)
	{
		List<int> result = [];

		for (int i = 0; i + 3 <= source.Length && result.Count < capacity; i += 3)
		{
			int d1 = source[i] + 256 * (source[i + 1] % 16);
			int d2 = source[i + 1] / 16 + 16 * source[i + 2];

			if (d1 < Q)
			{
				result.Add(d1);
			}

			if (d2 < Q && result.Count < capacity)
			{
				result.Add(d2);
			}
		}

		return result;
	}

	// K-PKE.KeyGen (Algorithm 13) up to ek_PKE (line 19), over the FIPS 202 transcription of KeccakReference.
	public static byte[] EncapsulationKey(ReadOnlySpan<byte> d, int k, int eta1)
	{
		byte[] rhoSigma = KeccakReference.Sha3([.. d, (byte)k], 64);
		byte[] rho = rhoSigma.AsSpan(0, 32).ToArray();
		byte[] sigma = rhoSigma.AsSpan(32).ToArray();
		int[][] s = [.. Enumerable.Range(0, k).Select(i => Ntt(SamplePolyCbd(Prf(sigma, i, eta1), eta1)))];
		int[][] e = [.. Enumerable.Range(0, k).Select(i => Ntt(SamplePolyCbd(Prf(sigma, k + i, eta1), eta1)))];
		byte[] encapsulationKey = new byte[384 * k + 32];

		for (int i = 0; i < k; ++i)
		{
			int[] t = e[i];

			for (int j = 0; j < k; ++j)
			{
				int[] product = MultiplyNtts(SampleNtt([.. rho, (byte)j, (byte)i]), s[j]);
				t = [.. t.Zip(product, static (a, b) => Mod(a + b))];
			}

			ByteEncode(t, 12).CopyTo(encapsulationKey, 384 * i);
		}

		rho.CopyTo(encapsulationKey, 384 * k);
		return encapsulationKey;
	}

	// Algorithm 7, over as many SHAKE128 blocks as it takes.
	public static int[] SampleNtt(ReadOnlySpan<byte> seed)
	{
		for (int blocks = 1; ; ++blocks)
		{
			List<int> coefficients = RejectSample(KeccakReference.Sponge(seed, 168, KeccakReference.ShakeDomainSeparator, 168 * blocks), N);

			if (coefficients.Count == N)
			{
				return [.. coefficients];
			}
		}
	}

	// Algorithm 8, bit by bit.
	public static int[] SamplePolyCbd(ReadOnlySpan<byte> source, int eta)
	{
		int[] result = new int[N];

		for (int i = 0; i < N; ++i)
		{
			int x = 0;
			int y = 0;

			for (int j = 0; j < eta; ++j)
			{
				x += Bit(source, 2 * i * eta + j);
				y += Bit(source, 2 * i * eta + eta + j);
			}

			result[i] = x - y;
		}

		return result;
	}

	// PRF_η(s, b) = SHAKE256(s ‖ b, 8 · 64 · η) (Sec. 4.1).
	private static byte[] Prf(byte[] seed, int b, int eta)
	{
		return KeccakReference.Sponge([.. seed, (byte)b], 136, KeccakReference.ShakeDomainSeparator, 64 * eta);
	}

	private static int Bit(ReadOnlySpan<byte> source, int index)
	{
		return source[index / 8] >> index % 8 & 1;
	}
}
