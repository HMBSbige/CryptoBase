using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// Splits a scalar u below an order n of 256 bits into v1 ≡ v2·u (mod n) with v1 and v2 below 2^128 in magnitude, v2 not 0: the extended Euclidean algorithm on (n, u) keeps each remainder r_i ≡ t_i·u (mod n), r_0 = n with t_0 = 0 and r_1 = u with t_1 = 1, the signs of t_i alternating, and stops at the first r_i below 2^128, where |t_i| ≤ n/r_(i − 1) < 2^128. Lehmer's algorithm (Knuth, TAOCP 4.5.2, Algorithm L) takes the steps on the leading 63 bits of the remainders where those fix the quotient and keep the next remainder at least 2^128, and a step on the whole remainders otherwise. The time depends on u, which must be public.
internal static class HalfScalars<TOrder> where TOrder : unmanaged, IMontgomeryModulus
{
	private const int Length = 4;

	// v1 in first, |v2| in second and whether v2 < 0.
	[SkipLocalsInit]
	internal static void Split(in FieldElement<TOrder> scalar, out UInt128 first, out UInt128 second, out bool negative)
	{
		Debug.Assert(TOrder.LimbCount is Length && TOrder.BitLength is 256);

		Span<ulong> limbs = stackalloc ulong[4 * (Length + 1)];
		Span<ulong> a = limbs.Slice(0, Length + 1);
		Span<ulong> b = limbs.Slice(Length + 1, Length + 1);
		Span<ulong> left = limbs.Slice(2 * (Length + 1), Length + 1);
		Span<ulong> right = limbs.Slice(3 * (Length + 1), Length + 1);
		TOrder.Modulus.CopyTo(a);
		FieldElement<TOrder>.GetLimbs(in scalar).CopyTo(b);
		a[Length] = 0;
		b[Length] = 0;
		// |t_(i − 1)| and |t_i| for b = r_i, and i − 1.
		UInt128 previous = 0;
		UInt128 current = 1;
		int steps = 0;

		while ((b[2] | b[3]) is not 0)
		{
			int shift = BitLength(a) - 63;
			long u = (long)ReadBits(a, shift);
			long v = (long)ReadBits(b, shift);
			// The next remainder lies above (v + min(c, d))·2^shift, which this bound keeps at least 2^128.
			long bound = shift >= 128 ? 1 : 1L << 128 - shift;
			// Knuth's A, B, C and D: the remainders after the steps so far are A·a + B·b and C·a + D·b.
			long x0 = 1;
			long y0 = 0;
			long x1 = 0;
			long y1 = 1;
			int taken = 0;

			while (true)
			{
				long lowDivisor = v + x1;
				long highDivisor = v + y1;
				long lowDividend = u + x0;
				long highDividend = u + y0;

				if (lowDivisor <= 0 || highDivisor <= 0 || lowDividend < 0 || highDividend < 0)
				{
					break;
				}

				// The quotient of the other bounds is q just if q·highDivisor ≤ highDividend < (q + 1)·highDivisor.
				ulong quotient = (ulong)lowDividend / (ulong)lowDivisor;
				ulong high = Multiply(quotient, (ulong)highDivisor, out ulong low);

				if (high is not 0 || low > (ulong)highDividend || (ulong)highDividend - low >= (ulong)highDivisor)
				{
					break;
				}

				long q = (long)quotient;

				long x2 = x0 - q * x1;
				long y2 = y0 - q * y1;
				long w = u - q * v;

				if (w + Math.Min(x2, y2) < bound)
				{
					break;
				}

				(x0, y0, x1, y1) = (x1, y1, x2, y2);
				(u, v) = (v, w);
				++taken;
			}

			if (taken is 0)
			{
				// One step on the whole remainders, after which b may fall below 2^128.
				UInt128 q = DivideRemainder(a, b);
				Span<ulong> remainder = a;
				a = b;
				b = remainder;
				(previous, current) = (current, previous + q * current);
				++steps;
				continue;
			}

			// The signs of A, B, C and D alternate with the steps: A > 0 > B, C < 0 < D after an even count, and the other way after an odd one. The remainders are not negative, and the magnitudes of the t_i add.
			ulong ax = (ulong)Math.Abs(x0);
			ulong ay = (ulong)Math.Abs(y0);
			ulong bx = (ulong)Math.Abs(x1);
			ulong by = (ulong)Math.Abs(y1);

			if ((taken & 1) is 0)
			{
				Combine(ax, a, ay, b, left);
				Combine(by, b, bx, a, right);
			}
			else
			{
				Combine(ay, b, ax, a, left);
				Combine(bx, a, by, b, right);
			}

			left.CopyTo(a);
			right.CopyTo(b);
			(previous, current) = (ax * previous + ay * current, bx * previous + by * current);
			steps += taken;
		}

		first = new UInt128(b[1], b[0]);
		second = current;
		negative = (steps & 1) is not 0;
	}

	// The bits of value, not 0.
	private static int BitLength(ReadOnlySpan<ulong> value)
	{
		for (int i = Length - 1; i > 0; --i)
		{
			if (value[i] is not 0)
			{
				return 64 * (i + 1) - BitOperations.LeadingZeroCount(value[i]);
			}
		}

		return 64 - BitOperations.LeadingZeroCount(value[0]);
	}

	// result = m·x − k·y, which the caller knows to lie in [0, 2^256).
	private static void Combine(ulong m, ReadOnlySpan<ulong> x, ulong k, ReadOnlySpan<ulong> y, Span<ulong> result)
	{
		Span<ulong> product = stackalloc ulong[Length + 1];
		result[Length] = MultiplyLimbs(ref MemoryMarshal.GetReference(x), m, ref result[0], Length);
		product[Length] = MultiplyLimbs(ref MemoryMarshal.GetReference(y), k, ref product[0], Length);
		_ = SubtractLimbs(ref result[0], ref product[0], ref result[0], Length + 1);
	}

	// Replaces a ≥ b ≥ 2^128 with a mod b and returns ⌊a/b⌋, below 2^128: one subtraction of b·2^i for each i from the difference of their lengths down, which is a few for the quotients that the steps of Lehmer leave.
	private static UInt128 DivideRemainder(Span<ulong> a, ReadOnlySpan<ulong> b)
	{
		Span<ulong> shifted = stackalloc ulong[Length + 1];
		Span<ulong> difference = stackalloc ulong[Length + 1];
		int count = BitLength(a) - BitLength(b);
		UInt128 quotient = 0;

		for (int i = count; i >= 0; --i)
		{
			ShiftLeft(b, i, shifted);

			if (SubtractLimbs(ref a[0], ref shifted[0], ref difference[0], Length) is 0)
			{
				difference.Slice(0, Length).CopyTo(a);
				quotient |= UInt128.One << i;
			}
		}

		return quotient;
	}

	// value·2^count for count below 128, within 256 bits.
	private static void ShiftLeft(ReadOnlySpan<ulong> value, int count, Span<ulong> result)
	{
		int words = count >> 6;
		int bits = count & 63;

		for (int i = Length - 1; i >= 0; --i)
		{
			ulong high = i - words >= 0 ? value[i - words] : 0;
			ulong low = i - words - 1 >= 0 ? value[i - words - 1] : 0;
			result[i] = high << bits | low >> 1 >> 63 - bits;
		}
	}
}
