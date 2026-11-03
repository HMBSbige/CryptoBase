using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Arithmetic with a public modulus or divisor below 2^34, such as the public exponent, on secret values: neither the time nor the addresses depend on the secret, which no division instruction sees.
internal static class SmallModulus
{
	internal const int MaxBits = 34;

	// value mod divisor for an odd divisor below 2^34, by Horner's rule over 16-bit pieces from the top. Each step is below 2^50, and a multiplication by ⌊(2^64 − 1)/divisor⌋ finds its quotient or one less, so that one conditional subtraction ends it.
	internal static ulong Remainder(ReadOnlySpan<ulong> value, ulong divisor)
	{
		Debug.Assert((divisor & 1) is 1 && divisor >> MaxBits is 0);

		ulong reciprocal = ulong.MaxValue / divisor;
		ulong remainder = 0;

		for (int i = value.Length - 1; i >= 0; --i)
		{
			ulong limb = value[i];

			for (int shift = 48; shift >= 0; shift -= 16)
			{
				ulong x = remainder << 16 | limb >> shift & 0xFFFF;
				ulong quotient = Math.BigMul(x, reciprocal, out _);
				remainder = ReduceOnce(x - quotient * divisor, divisor);
			}
		}

		return remainder;
	}

	// All ones if gcd(x, modulus) = 1, for an odd modulus and x below it, by binary steps on 64-bit words: u ← (u − v)/2 or u/2 with v odd throughout, swapping first when u is odd and below v. Each step halves u or the larger of the two, so 2·34 steps bring u to 0 and leave the gcd in v.
	internal static ulong IsCoprime(ulong x, ulong modulus)
	{
		Debug.Assert((modulus & 1) is 1 && x < modulus && modulus >> MaxBits is 0);

		ulong u = x;
		ulong v = modulus;

		for (int i = 0; i < 2 * MaxBits; ++i)
		{
			ulong odd = 0 - (u & 1);
			ulong swap = odd & LessThan(u, v);
			ulong delta = (u ^ v) & swap;
			u ^= delta;
			v ^= delta;
			u -= v & odd;
			u >>= 1;
		}

		return LimbArithmetic.ZeroMask(v ^ 1);
	}

	// x⁻¹ mod modulus for an odd modulus and x coprime to it, below it, by the same steps with a ≡ u/x and c ≡ v/x tracked alongside, halving a modulo the modulus.
	internal static ulong Inverse(ulong x, ulong modulus)
	{
		Debug.Assert((modulus & 1) is 1 && x < modulus && modulus >> MaxBits is 0);

		ulong u = x;
		ulong v = modulus;
		ulong a = 1;
		ulong c = 0;

		for (int i = 0; i < 2 * MaxBits; ++i)
		{
			ulong odd = 0 - (u & 1);
			ulong swap = odd & LessThan(u, v);
			ulong delta = (u ^ v) & swap;
			u ^= delta;
			v ^= delta;
			delta = (a ^ c) & swap;
			a ^= delta;
			c ^= delta;
			u -= v & odd;
			// a − c mod modulus, both below it.
			a = a - (c & odd) + (modulus & LessThan(a, c & odd));
			u >>= 1;
			// a/2 mod modulus: an odd a gains the odd modulus first.
			a = a + (modulus & 0 - (a & 1)) >> 1;
		}

		return c;
	}

	// value = value/divisor for a value that the odd divisor divides, limb by limb from the bottom with divisor⁻¹ mod 2^64: each limb of the quotient is the one that clears the limb of what remains.
	internal static void DivideExact(Span<ulong> value, ulong divisor)
	{
		Debug.Assert((divisor & 1) is 1);

		ulong inverse = Limbs.InvertWord(divisor);
		ulong borrow = 0;

		for (int i = 0; i < value.Length; ++i)
		{
			ulong limb = value[i];
			ulong difference = limb - borrow;
			ulong quotient = difference * inverse;
			value[i] = quotient;
			// The borrow of the subtraction, and the part of quotient·divisor above this limb.
			borrow = Unsafe.BitCast<bool, byte>(limb < borrow) + Math.BigMul(quotient, divisor, out _);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong ReduceOnce(ulong value, ulong modulus)
	{
		ulong difference = value - modulus;
		return LimbArithmetic.Select(0 - (difference >> 63), value, difference);
	}

	// All ones if x < y, for x and y below 2^63.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong LessThan(ulong x, ulong y)
	{
		return 0 - (x - y >> 63);
	}
}
