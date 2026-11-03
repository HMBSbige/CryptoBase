using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Natural numbers as 64-bit limbs, least significant first, of any number of limbs. A mask is all ones or zero. Unless a method says otherwise, neither the time nor the addresses depend on the values, only on the lengths, and a result may be the same span as an input but must not overlap one otherwise.
internal static class Limbs
{
	// Reads big-endian bytes, which may have leading zeros, into limbs, which must hold them.
	internal static void FromBigEndian(ReadOnlySpan<byte> source, Span<ulong> destination)
	{
		Debug.Assert(source.Length <= destination.Length * sizeof(ulong));

		destination.Clear();
		int whole = source.Length / sizeof(ulong);

		for (int i = 0; i < whole; ++i)
		{
			destination[i] = BinaryPrimitives.ReadUInt64BigEndian(source.Slice(source.Length - (i + 1) * sizeof(ulong)));
		}

		ReadOnlySpan<byte> rest = source.Slice(0, source.Length - whole * sizeof(ulong));
		ulong limb = 0;

		foreach (byte value in rest)
		{
			limb = limb << 8 | value;
		}

		if (!rest.IsEmpty)
		{
			destination[whole] = limb;
		}
	}

	// Writes the limbs as big-endian bytes, which must hold the value: limbs past the end of destination must be zero.
	internal static void ToBigEndian(ReadOnlySpan<ulong> source, Span<byte> destination)
	{
		int whole = Math.Min(destination.Length / sizeof(ulong), source.Length);

		for (int i = 0; i < whole; ++i)
		{
			BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(destination.Length - (i + 1) * sizeof(ulong)), source[i]);
		}

		Span<byte> rest = destination.Slice(0, destination.Length - whole * sizeof(ulong));
		ulong limb = whole < source.Length ? source[whole] : 0;

		for (int i = rest.Length - 1; i >= 0; --i)
		{
			rest[i] = (byte)limb;
			limb >>= 8;
		}
	}

	// The number of limbs up to the most significant nonzero one. Variable time: the result is the length that a value occupies.
	internal static int GetLength(ReadOnlySpan<ulong> value)
	{
		int length = value.Length;

		while (length > 0 && value[length - 1] is 0)
		{
			--length;
		}

		return length;
	}

	// Variable time, for public values.
	internal static int GetBitLength(ReadOnlySpan<ulong> value)
	{
		int length = GetLength(value);
		return length is 0 ? 0 : 64 * length - BitOperations.LeadingZeroCount(value[length - 1]);
	}

	// GetBitLength for secret values: every limb is read, the top nonzero one is taken with masks, and its bit length found by halving it with masks, without the table that BitOperations reads from without the instruction.
	internal static int GetSecretBitLength(ReadOnlySpan<ulong> value)
	{
		ulong top = 0;
		ulong below = 0;

		for (int i = 0; i < value.Length; ++i)
		{
			ulong nonzero = ~LimbArithmetic.ZeroMask(value[i]);
			top = LimbArithmetic.Select(nonzero, value[i], top);
			below = LimbArithmetic.Select(nonzero, (ulong)(64 * i), below);
		}

		ulong bits = 0;

		for (int shift = 32; shift > 0; shift >>= 1)
		{
			ulong upper = top >> shift;
			ulong nonzero = ~LimbArithmetic.ZeroMask(upper);
			bits += (ulong)shift & nonzero;
			top = LimbArithmetic.Select(nonzero, upper, top);
		}

		// top is now 1, or 0 for a value of 0.
		return (int)(below + bits + top);
	}

	// sum = left + right, all of one length; returns the carry.
	internal static ulong Add(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> sum)
	{
		Debug.Assert(right.Length == left.Length && sum.Length == left.Length);

		ulong carry = 0;

		for (int i = 0; i < left.Length; ++i)
		{
			sum[i] = LimbArithmetic.AddWithCarry(left[i], right[i], ref carry);
		}

		return carry;
	}

	// value += addend, for an addend no longer than value; returns the carry out of value.
	internal static ulong AddInPlace(Span<ulong> value, ReadOnlySpan<ulong> addend)
	{
		Debug.Assert(addend.Length <= value.Length);

		ulong carry = 0;

		for (int i = 0; i < value.Length; ++i)
		{
			value[i] = LimbArithmetic.AddWithCarry(value[i], i < addend.Length ? addend[i] : 0, ref carry);
		}

		return carry;
	}

	// difference = left − right, all of one length; returns the borrow.
	internal static ulong Subtract(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> difference)
	{
		Debug.Assert(right.Length == left.Length && difference.Length == left.Length);

		ulong borrow = 0;

		for (int i = 0; i < left.Length; ++i)
		{
			difference[i] = LimbArithmetic.SubtractWithBorrow(left[i], right[i], ref borrow);
		}

		return borrow;
	}

	// value −= small; returns the borrow.
	internal static ulong SubtractSmall(Span<ulong> value, ulong small)
	{
		ulong borrow = 0;

		for (int i = 0; i < value.Length; ++i)
		{
			value[i] = LimbArithmetic.SubtractWithBorrow(value[i], i is 0 ? small : 0, ref borrow);
		}

		return borrow;
	}

	// All ones if left < right, for values that may differ in length.
	internal static ulong LessThan(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
	{
		int length = Math.Max(left.Length, right.Length);
		ulong borrow = 0;

		for (int i = 0; i < length; ++i)
		{
			_ = LimbArithmetic.SubtractWithBorrow(i < left.Length ? left[i] : 0, i < right.Length ? right[i] : 0, ref borrow);
		}

		return 0 - borrow;
	}

	internal static ulong IsZero(ReadOnlySpan<ulong> value)
	{
		ulong bits = 0;

		foreach (ulong limb in value)
		{
			bits |= limb;
		}

		return LimbArithmetic.ZeroMask(bits);
	}

	// For values that may differ in length.
	internal static ulong Equal(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
	{
		int length = Math.Max(left.Length, right.Length);
		ulong bits = 0;

		for (int i = 0; i < length; ++i)
		{
			bits |= (i < left.Length ? left[i] : 0) ^ (i < right.Length ? right[i] : 0);
		}

		return LimbArithmetic.ZeroMask(bits);
	}

	internal static ulong EqualSmall(ReadOnlySpan<ulong> value, ulong small)
	{
		ulong bits = 0;

		for (int i = 0; i < value.Length; ++i)
		{
			bits |= value[i] ^ (i is 0 ? small : 0);
		}

		return LimbArithmetic.ZeroMask(bits);
	}

	internal static void Select(ulong mask, ReadOnlySpan<ulong> whenSet, ReadOnlySpan<ulong> whenClear, Span<ulong> result)
	{
		Debug.Assert(whenSet.Length == result.Length && whenClear.Length == result.Length);

		for (int i = 0; i < result.Length; ++i)
		{
			result[i] = LimbArithmetic.Select(mask, whenSet[i], whenClear[i]);
		}
	}

	// product = left·right, of left.Length + right.Length limbs.
	internal static void Multiply(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> product)
	{
		Debug.Assert(product.Length == left.Length + right.Length);
		Debug.Assert(!product.Overlaps(left) && !product.Overlaps(right));

		product.Clear();

		for (int i = 0; i < right.Length; ++i)
		{
			product[i + left.Length] = MultiplyAdd(left, right[i], product.Slice(i, left.Length));
		}
	}

	// accumulator += x·y, for an accumulator as long as x; returns the limb above it.
	internal static ulong MultiplyAdd(ReadOnlySpan<ulong> x, ulong y, Span<ulong> accumulator)
	{
		Debug.Assert(accumulator.Length == x.Length);

		ulong carry = 0;

		for (int i = 0; i < x.Length; ++i)
		{
			carry = LimbArithmetic.MultiplyAdd(x[i], y, accumulator[i], carry, out ulong low);
			accumulator[i] = low;
		}

		return carry;
	}

	// value = value·small + addend; returns the limb above it.
	internal static ulong MultiplySmall(Span<ulong> value, ulong small, ulong addend)
	{
		ulong carry = addend;

		for (int i = 0; i < value.Length; ++i)
		{
			carry = LimbArithmetic.MultiplyAdd(value[i], small, carry, 0, out ulong low);
			value[i] = low;
		}

		return carry;
	}

	// 1/value mod 2^64 for an odd value: each Newton step doubles the bits that are right, from the 5 of 3·value ⊕ 2.
	internal static ulong InvertWord(ulong value)
	{
		Debug.Assert((value & 1) is 1);

		ulong inverse = 3 * value ^ 2;
		inverse *= 2 - value * inverse;
		inverse *= 2 - value * inverse;
		inverse *= 2 - value * inverse;
		inverse *= 2 - value * inverse;
		return inverse;
	}

	// Sets remainder to dividend mod divisor, by shifting the dividend in bit by bit and subtracting the divisor whenever the remainder reaches it. divisor must have a nonzero top limb, and remainder its length. A zero divisor gives an unspecified remainder rather than an exception.
	internal static void Remainder(ReadOnlySpan<ulong> dividend, ReadOnlySpan<ulong> divisor, Span<ulong> remainder, Span<ulong> scratch)
	{
		int length = divisor.Length;

		Debug.Assert(remainder.Length == length && scratch.Length >= length);

		// The top length − 1 limbs of the dividend are below the divisor, whose top limb is not zero, and so start the remainder.
		int start = Math.Max(dividend.Length - (length - 1), 0);
		remainder.Clear();
		dividend.Slice(start).CopyTo(remainder);

		for (int i = start - 1; i >= 0; --i)
		{
			ulong limb = dividend[i];

			for (int bit = 63; bit >= 0; --bit)
			{
				// remainder < divisor, so 2·remainder + bit < 2·divisor and one subtraction suffices; top is the bit shifted out.
				ulong top = remainder[length - 1] >> 63;

				for (int j = length - 1; j > 0; --j)
				{
					remainder[j] = remainder[j] << 1 | remainder[j - 1] >> 63;
				}

				remainder[0] = remainder[0] << 1 | limb >> bit & 1;
				ulong borrow = Subtract(remainder, divisor, scratch.Slice(0, length));
				Select(0 - (top | borrow ^ 1), scratch.Slice(0, length), remainder, remainder);
			}
		}
	}

	// The number of trailing zero bits, 64·value.Length for zero. Bit by bit: the fallback of BitOperations without the instruction reads a table at an index that depends on the value.
	internal static int TrailingZeroCount(ReadOnlySpan<ulong> value)
	{
		ulong found = 0;
		ulong count = 0;

		foreach (ulong limb in value)
		{
			for (int bit = 0; bit < 64; ++bit)
			{
				found |= limb >> bit & 1;
				count += found ^ 1;
			}
		}

		return (int)count;
	}

	// value >>= shift for a secret shift below 64·value.Length, in one conditional shift per bit of the shift.
	internal static void ShiftRight(Span<ulong> value, int shift)
	{
		Debug.Assert((uint)shift < (uint)(64 * value.Length));

		for (int step = 1; step < 64 * value.Length; step <<= 1)
		{
			ulong mask = 0 - (ulong)(shift >> BitOperations.TrailingZeroCount(step) & 1);
			int limbs = step >> 6;
			int bits = step & 63;

			for (int i = 0; i < value.Length; ++i)
			{
				ulong low = i + limbs < value.Length ? value[i + limbs] : 0;
				ulong high = i + limbs + 1 < value.Length ? value[i + limbs + 1] : 0;
				// high << 1 << 63 − bits is high << 64 − bits, and 0 for bits = 0.
				ulong shifted = low >> bits | high << 1 << 63 - bits;
				value[i] = LimbArithmetic.Select(mask, shifted, value[i]);
			}
		}
	}

	// quotient = dividend / divisor and remainder = dividend mod divisor, bit by bit from the top, for a divisor that is not zero; remainder and scratch have the length of the divisor, quotient that of the dividend.
	internal static void Divide(ReadOnlySpan<ulong> dividend, ReadOnlySpan<ulong> divisor, Span<ulong> quotient, Span<ulong> remainder, Span<ulong> scratch)
	{
		int length = divisor.Length;

		Debug.Assert(quotient.Length == dividend.Length && remainder.Length == length && scratch.Length >= length);

		remainder.Clear();
		quotient.Clear();

		for (int i = dividend.Length - 1; i >= 0; --i)
		{
			ulong limb = dividend[i];
			ulong bits = 0;

			for (int bit = 63; bit >= 0; --bit)
			{
				ulong top = remainder[length - 1] >> 63;

				for (int j = length - 1; j > 0; --j)
				{
					remainder[j] = remainder[j] << 1 | remainder[j - 1] >> 63;
				}

				remainder[0] = remainder[0] << 1 | limb >> bit & 1;
				ulong borrow = Subtract(remainder, divisor, scratch.Slice(0, length));
				ulong take = top | borrow ^ 1;
				Select(0 - take, scratch.Slice(0, length), remainder, remainder);
				bits |= take << bit;
			}

			quotient[i] = bits;
		}
	}

	// The odd part of gcd(x, y) and the power of two in it, for values of one length, not both zero, by Stein's binary steps: subtract the smaller from the larger when both are odd, then halve each that is even, counting the halvings that both share. Every step halves one of them at least, so 128 steps per limb bring one to zero.
	internal static int Gcd(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> oddPart, Span<ulong> scratch)
	{
		int length = x.Length;

		Debug.Assert(y.Length == length && oddPart.Length == length && scratch.Length >= 2 * length);

		Span<ulong> u = oddPart;
		Span<ulong> v = scratch.Slice(0, length);
		Span<ulong> difference = scratch.Slice(length, length);
		x.CopyTo(u);
		y.CopyTo(v);
		int shift = 0;

		for (int i = 0; i < 128 * length; ++i)
		{
			ulong bothOdd = 0 - (u[0] & v[0] & 1);
			ulong uBelow = 0 - Subtract(u, v, difference);
			Select(bothOdd & ~uBelow, difference, u, u);
			_ = Subtract(v, u, difference);
			Select(bothOdd & uBelow, difference, v, v);
			ulong uEven = u[0] & 1 ^ 1;
			ulong vEven = v[0] & 1 ^ 1;
			shift += (int)(uEven & vEven);
			ShiftRightOnce(u, 0 - uEven);
			ShiftRightOnce(v, 0 - vEven);
		}

		// One of them is zero.
		for (int i = 0; i < length; ++i)
		{
			u[i] |= v[i];
		}

		return shift;
	}

	// value >>= 1 where mask is all ones.
	private static void ShiftRightOnce(Span<ulong> value, ulong mask)
	{
		for (int i = 0; i < value.Length; ++i)
		{
			ulong above = i + 1 < value.Length ? value[i + 1] : 0;
			value[i] = LimbArithmetic.Select(mask, value[i] >> 1 | above << 63, value[i]);
		}
	}
}
