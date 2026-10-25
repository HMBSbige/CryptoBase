namespace CryptoBase.EllipticCurves;

// Carries and borrows are 0 or 1. A comparison taken as a value, as in Carry and Borrow, compiles to a flag read such as setb or cset and not to a branch. The methods on limb sequences take count limbs, least significant first, and are unrolled up to MaxLimbCount so that a constant count drops the steps beyond it. A result may be the same sequence as an input unless a method says otherwise.
internal static class LimbArithmetic
{
	internal const int MaxLimbCount = 9;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong AddWithCarry(ulong x, ulong y, ref ulong carry)
	{
		ulong sum = x + y + carry;
		carry = (x & y | (x | y) & ~sum) >> 63;
		return sum;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong SubtractWithBorrow(ulong x, ulong y, ref ulong borrow)
	{
		ulong difference = x - y - borrow;
		borrow = (~x & y | ~(x ^ y) & difference) >> 63;
		return difference;
	}

	// The carry out of sum = augend + addend.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong Carry(ulong sum, ulong addend)
	{
		return Unsafe.BitCast<bool, byte>(sum < addend);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong Borrow(ulong minuend, ulong subtrahend)
	{
		return Unsafe.BitCast<bool, byte>(minuend < subtrahend);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong Multiply(ulong x, ulong y, out ulong low)
	{
		// With BMI2, Math.BigMul passes the low limb through memory; a separate multiplication keeps both limbs in registers.
		if (Bmi2.X64.IsSupported)
		{
			low = x * y;
			return Bmi2.X64.MultiplyNoFlags(x, y);
		}

		// The same multiplications as Math.BigMul, without inlining its body, which leaves the JIT room to inline the rest of a product.
		if (ArmBase.Arm64.IsSupported)
		{
			low = x * y;
			return ArmBase.Arm64.MultiplyHigh(x, y);
		}

		return Math.BigMul(x, y, out low);
	}

	// x · y + a + b is at most 2^128 − 1, so the high limb does not overflow.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong MultiplyAdd(ulong x, ulong y, ulong a, ulong b, out ulong low)
	{
		ulong high = Multiply(x, y, out ulong product);
		product += a;
		high += Carry(product, a);
		product += b;
		low = product;
		return high + Carry(product, b);
	}

	// Returns ulong.MaxValue if value is zero and zero otherwise.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong ZeroMask(ulong value)
	{
		return ((value | 0 - value) >> 63) - 1;
	}

	// Sets sum to x + (y & mask) and returns the carry out.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong AddLimbs(ref ulong x, ref ulong y, ulong mask, ref ulong sum, int count)
	{
		Debug.Assert(count is > 0 and <= MaxLimbCount);

		ulong carry = 0;
		sum = AddWithCarry(x, y & mask, ref carry);
		if (count > 1)
		{
			Unsafe.Add(ref sum, 1) = AddWithCarry(Unsafe.Add(ref x, 1), Unsafe.Add(ref y, 1) & mask, ref carry);
		}

		if (count > 2)
		{
			Unsafe.Add(ref sum, 2) = AddWithCarry(Unsafe.Add(ref x, 2), Unsafe.Add(ref y, 2) & mask, ref carry);
		}

		if (count > 3)
		{
			Unsafe.Add(ref sum, 3) = AddWithCarry(Unsafe.Add(ref x, 3), Unsafe.Add(ref y, 3) & mask, ref carry);
		}

		if (count > 4)
		{
			Unsafe.Add(ref sum, 4) = AddWithCarry(Unsafe.Add(ref x, 4), Unsafe.Add(ref y, 4) & mask, ref carry);
		}

		if (count > 5)
		{
			Unsafe.Add(ref sum, 5) = AddWithCarry(Unsafe.Add(ref x, 5), Unsafe.Add(ref y, 5) & mask, ref carry);
		}

		if (count > 6)
		{
			Unsafe.Add(ref sum, 6) = AddWithCarry(Unsafe.Add(ref x, 6), Unsafe.Add(ref y, 6) & mask, ref carry);
		}

		if (count > 7)
		{
			Unsafe.Add(ref sum, 7) = AddWithCarry(Unsafe.Add(ref x, 7), Unsafe.Add(ref y, 7) & mask, ref carry);
		}

		if (count > 8)
		{
			Unsafe.Add(ref sum, 8) = AddWithCarry(Unsafe.Add(ref x, 8), Unsafe.Add(ref y, 8) & mask, ref carry);
		}

		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong SubtractLimbs(ref ulong x, ref ulong y, ref ulong difference, int count)
	{
		Debug.Assert(count is > 0 and <= MaxLimbCount);

		ulong borrow = 0;
		difference = SubtractWithBorrow(x, y, ref borrow);
		if (count > 1)
		{
			Unsafe.Add(ref difference, 1) = SubtractWithBorrow(Unsafe.Add(ref x, 1), Unsafe.Add(ref y, 1), ref borrow);
		}

		if (count > 2)
		{
			Unsafe.Add(ref difference, 2) = SubtractWithBorrow(Unsafe.Add(ref x, 2), Unsafe.Add(ref y, 2), ref borrow);
		}

		if (count > 3)
		{
			Unsafe.Add(ref difference, 3) = SubtractWithBorrow(Unsafe.Add(ref x, 3), Unsafe.Add(ref y, 3), ref borrow);
		}

		if (count > 4)
		{
			Unsafe.Add(ref difference, 4) = SubtractWithBorrow(Unsafe.Add(ref x, 4), Unsafe.Add(ref y, 4), ref borrow);
		}

		if (count > 5)
		{
			Unsafe.Add(ref difference, 5) = SubtractWithBorrow(Unsafe.Add(ref x, 5), Unsafe.Add(ref y, 5), ref borrow);
		}

		if (count > 6)
		{
			Unsafe.Add(ref difference, 6) = SubtractWithBorrow(Unsafe.Add(ref x, 6), Unsafe.Add(ref y, 6), ref borrow);
		}

		if (count > 7)
		{
			Unsafe.Add(ref difference, 7) = SubtractWithBorrow(Unsafe.Add(ref x, 7), Unsafe.Add(ref y, 7), ref borrow);
		}

		if (count > 8)
		{
			Unsafe.Add(ref difference, 8) = SubtractWithBorrow(Unsafe.Add(ref x, 8), Unsafe.Add(ref y, 8), ref borrow);
		}

		return borrow;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SelectLimbs(ulong mask, ref ulong whenSet, ref ulong whenClear, ref ulong result, int count)
	{
		Debug.Assert(count is > 0 and <= MaxLimbCount);

		result = Select(mask, whenSet, whenClear);
		if (count > 1)
		{
			Unsafe.Add(ref result, 1) = Select(mask, Unsafe.Add(ref whenSet, 1), Unsafe.Add(ref whenClear, 1));
		}

		if (count > 2)
		{
			Unsafe.Add(ref result, 2) = Select(mask, Unsafe.Add(ref whenSet, 2), Unsafe.Add(ref whenClear, 2));
		}

		if (count > 3)
		{
			Unsafe.Add(ref result, 3) = Select(mask, Unsafe.Add(ref whenSet, 3), Unsafe.Add(ref whenClear, 3));
		}

		if (count > 4)
		{
			Unsafe.Add(ref result, 4) = Select(mask, Unsafe.Add(ref whenSet, 4), Unsafe.Add(ref whenClear, 4));
		}

		if (count > 5)
		{
			Unsafe.Add(ref result, 5) = Select(mask, Unsafe.Add(ref whenSet, 5), Unsafe.Add(ref whenClear, 5));
		}

		if (count > 6)
		{
			Unsafe.Add(ref result, 6) = Select(mask, Unsafe.Add(ref whenSet, 6), Unsafe.Add(ref whenClear, 6));
		}

		if (count > 7)
		{
			Unsafe.Add(ref result, 7) = Select(mask, Unsafe.Add(ref whenSet, 7), Unsafe.Add(ref whenClear, 7));
		}

		if (count > 8)
		{
			Unsafe.Add(ref result, 8) = Select(mask, Unsafe.Add(ref whenSet, 8), Unsafe.Add(ref whenClear, 8));
		}
	}

	// product must not overlap x.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong MultiplyLimbs(ref ulong x, ulong y, ref ulong product, int count)
	{
		Debug.Assert(count is > 0 and <= MaxLimbCount);

		ulong carry = Multiply(x, y, out product);
		if (count > 1)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 1), y, carry, 0, out Unsafe.Add(ref product, 1));
		}

		if (count > 2)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 2), y, carry, 0, out Unsafe.Add(ref product, 2));
		}

		if (count > 3)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 3), y, carry, 0, out Unsafe.Add(ref product, 3));
		}

		if (count > 4)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 4), y, carry, 0, out Unsafe.Add(ref product, 4));
		}

		if (count > 5)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 5), y, carry, 0, out Unsafe.Add(ref product, 5));
		}

		if (count > 6)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 6), y, carry, 0, out Unsafe.Add(ref product, 6));
		}

		if (count > 7)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 7), y, carry, 0, out Unsafe.Add(ref product, 7));
		}

		if (count > 8)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 8), y, carry, 0, out Unsafe.Add(ref product, 8));
		}

		return carry;
	}

	// accumulator must not overlap x.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong MultiplyAddLimbs(ref ulong x, ulong y, ref ulong accumulator, int count)
	{
		Debug.Assert(count is > 0 and <= MaxLimbCount);

		ulong carry = MultiplyAdd(x, y, accumulator, 0, out accumulator);
		if (count > 1)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 1), y, Unsafe.Add(ref accumulator, 1), carry, out Unsafe.Add(ref accumulator, 1));
		}

		if (count > 2)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 2), y, Unsafe.Add(ref accumulator, 2), carry, out Unsafe.Add(ref accumulator, 2));
		}

		if (count > 3)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 3), y, Unsafe.Add(ref accumulator, 3), carry, out Unsafe.Add(ref accumulator, 3));
		}

		if (count > 4)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 4), y, Unsafe.Add(ref accumulator, 4), carry, out Unsafe.Add(ref accumulator, 4));
		}

		if (count > 5)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 5), y, Unsafe.Add(ref accumulator, 5), carry, out Unsafe.Add(ref accumulator, 5));
		}

		if (count > 6)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 6), y, Unsafe.Add(ref accumulator, 6), carry, out Unsafe.Add(ref accumulator, 6));
		}

		if (count > 7)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 7), y, Unsafe.Add(ref accumulator, 7), carry, out Unsafe.Add(ref accumulator, 7));
		}

		if (count > 8)
		{
			carry = MultiplyAdd(Unsafe.Add(ref x, 8), y, Unsafe.Add(ref accumulator, 8), carry, out Unsafe.Add(ref accumulator, 8));
		}

		return carry;
	}

	// Sets t0 to t7 to the product of the four-limb x and y, in locals rather than in memory.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyLimbs(ref ulong x, ref ulong y, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7)
	{
		ulong x0 = x;
		ulong x1 = Unsafe.Add(ref x, 1);
		ulong x2 = Unsafe.Add(ref x, 2);
		ulong x3 = Unsafe.Add(ref x, 3);
		ulong word = y;
		ulong carry = Multiply(x0, word, out t0);
		carry = MultiplyAdd(x1, word, carry, 0, out t1);
		carry = MultiplyAdd(x2, word, carry, 0, out t2);
		t4 = MultiplyAdd(x3, word, carry, 0, out t3);
		word = Unsafe.Add(ref y, 1);
		carry = MultiplyAdd(x0, word, t1, 0, out t1);
		carry = MultiplyAdd(x1, word, t2, carry, out t2);
		carry = MultiplyAdd(x2, word, t3, carry, out t3);
		t5 = MultiplyAdd(x3, word, t4, carry, out t4);
		word = Unsafe.Add(ref y, 2);
		carry = MultiplyAdd(x0, word, t2, 0, out t2);
		carry = MultiplyAdd(x1, word, t3, carry, out t3);
		carry = MultiplyAdd(x2, word, t4, carry, out t4);
		t6 = MultiplyAdd(x3, word, t5, carry, out t5);
		word = Unsafe.Add(ref y, 3);
		carry = MultiplyAdd(x0, word, t3, 0, out t3);
		carry = MultiplyAdd(x1, word, t4, carry, out t4);
		carry = MultiplyAdd(x2, word, t5, carry, out t5);
		t7 = MultiplyAdd(x3, word, t6, carry, out t6);
	}

	// As MultiplyLimbs with y = x: the cross products once, doubled, plus the squares of the limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SquareLimbs(ref ulong x, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7)
	{
		ulong x0 = x;
		ulong x1 = Unsafe.Add(ref x, 1);
		ulong x2 = Unsafe.Add(ref x, 2);
		ulong x3 = Unsafe.Add(ref x, 3);
		ulong carry = Multiply(x1, x0, out ulong c1);
		carry = MultiplyAdd(x2, x0, carry, 0, out ulong c2);
		ulong c4 = MultiplyAdd(x3, x0, carry, 0, out ulong c3);
		carry = MultiplyAdd(x2, x1, c3, 0, out c3);
		ulong c5 = MultiplyAdd(x3, x1, c4, carry, out c4);
		ulong c6 = MultiplyAdd(x3, x2, c5, 0, out c5);
		ulong h0 = Multiply(x0, x0, out t0);
		ulong h1 = Multiply(x1, x1, out ulong l1);
		ulong h2 = Multiply(x2, x2, out ulong l2);
		ulong h3 = Multiply(x3, x3, out ulong l3);
		carry = 0;
		t1 = AddWithCarry(c1 << 1, h0, ref carry);
		t2 = AddWithCarry(c2 << 1 | c1 >> 63, l1, ref carry);
		t3 = AddWithCarry(c3 << 1 | c2 >> 63, h1, ref carry);
		t4 = AddWithCarry(c4 << 1 | c3 >> 63, l2, ref carry);
		t5 = AddWithCarry(c5 << 1 | c4 >> 63, h2, ref carry);
		t6 = AddWithCarry(c6 << 1 | c5 >> 63, l3, ref carry);
		// x² is below 2^512, so the top limb does not wrap.
		t7 = (c6 >> 63) + h3 + carry;
	}

	// Sets t0 to t11 to the product of the six-limb x and y, in locals rather than in memory.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplyLimbs(ref ulong x, ref ulong y, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9, out ulong t10, out ulong t11)
	{
		ulong x0 = x;
		ulong x1 = Unsafe.Add(ref x, 1);
		ulong x2 = Unsafe.Add(ref x, 2);
		ulong x3 = Unsafe.Add(ref x, 3);
		ulong x4 = Unsafe.Add(ref x, 4);
		ulong x5 = Unsafe.Add(ref x, 5);
		ulong word = y;
		ulong carry = Multiply(x0, word, out t0);
		carry = MultiplyAdd(x1, word, carry, 0, out t1);
		carry = MultiplyAdd(x2, word, carry, 0, out t2);
		carry = MultiplyAdd(x3, word, carry, 0, out t3);
		carry = MultiplyAdd(x4, word, carry, 0, out t4);
		t6 = MultiplyAdd(x5, word, carry, 0, out t5);
		word = Unsafe.Add(ref y, 1);
		carry = MultiplyAdd(x0, word, t1, 0, out t1);
		carry = MultiplyAdd(x1, word, t2, carry, out t2);
		carry = MultiplyAdd(x2, word, t3, carry, out t3);
		carry = MultiplyAdd(x3, word, t4, carry, out t4);
		carry = MultiplyAdd(x4, word, t5, carry, out t5);
		t7 = MultiplyAdd(x5, word, t6, carry, out t6);
		word = Unsafe.Add(ref y, 2);
		carry = MultiplyAdd(x0, word, t2, 0, out t2);
		carry = MultiplyAdd(x1, word, t3, carry, out t3);
		carry = MultiplyAdd(x2, word, t4, carry, out t4);
		carry = MultiplyAdd(x3, word, t5, carry, out t5);
		carry = MultiplyAdd(x4, word, t6, carry, out t6);
		t8 = MultiplyAdd(x5, word, t7, carry, out t7);
		word = Unsafe.Add(ref y, 3);
		carry = MultiplyAdd(x0, word, t3, 0, out t3);
		carry = MultiplyAdd(x1, word, t4, carry, out t4);
		carry = MultiplyAdd(x2, word, t5, carry, out t5);
		carry = MultiplyAdd(x3, word, t6, carry, out t6);
		carry = MultiplyAdd(x4, word, t7, carry, out t7);
		t9 = MultiplyAdd(x5, word, t8, carry, out t8);
		word = Unsafe.Add(ref y, 4);
		carry = MultiplyAdd(x0, word, t4, 0, out t4);
		carry = MultiplyAdd(x1, word, t5, carry, out t5);
		carry = MultiplyAdd(x2, word, t6, carry, out t6);
		carry = MultiplyAdd(x3, word, t7, carry, out t7);
		carry = MultiplyAdd(x4, word, t8, carry, out t8);
		t10 = MultiplyAdd(x5, word, t9, carry, out t9);
		word = Unsafe.Add(ref y, 5);
		carry = MultiplyAdd(x0, word, t5, 0, out t5);
		carry = MultiplyAdd(x1, word, t6, carry, out t6);
		carry = MultiplyAdd(x2, word, t7, carry, out t7);
		carry = MultiplyAdd(x3, word, t8, carry, out t8);
		carry = MultiplyAdd(x4, word, t9, carry, out t9);
		t11 = MultiplyAdd(x5, word, t10, carry, out t10);
	}

	// As MultiplyLimbs with y = x: the cross products once, doubled, plus the squares of the limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SquareLimbs(ref ulong x, out ulong t0, out ulong t1, out ulong t2, out ulong t3, out ulong t4, out ulong t5, out ulong t6, out ulong t7, out ulong t8, out ulong t9, out ulong t10, out ulong t11)
	{
		ulong x0 = x;
		ulong x1 = Unsafe.Add(ref x, 1);
		ulong x2 = Unsafe.Add(ref x, 2);
		ulong x3 = Unsafe.Add(ref x, 3);
		ulong x4 = Unsafe.Add(ref x, 4);
		ulong x5 = Unsafe.Add(ref x, 5);
		ulong carry = Multiply(x1, x0, out ulong c1);
		carry = MultiplyAdd(x2, x0, carry, 0, out ulong c2);
		carry = MultiplyAdd(x3, x0, carry, 0, out ulong c3);
		carry = MultiplyAdd(x4, x0, carry, 0, out ulong c4);
		ulong c6 = MultiplyAdd(x5, x0, carry, 0, out ulong c5);
		carry = MultiplyAdd(x2, x1, c3, 0, out c3);
		carry = MultiplyAdd(x3, x1, c4, carry, out c4);
		carry = MultiplyAdd(x4, x1, c5, carry, out c5);
		ulong c7 = MultiplyAdd(x5, x1, c6, carry, out c6);
		carry = MultiplyAdd(x3, x2, c5, 0, out c5);
		carry = MultiplyAdd(x4, x2, c6, carry, out c6);
		ulong c8 = MultiplyAdd(x5, x2, c7, carry, out c7);
		carry = MultiplyAdd(x4, x3, c7, 0, out c7);
		ulong c9 = MultiplyAdd(x5, x3, c8, carry, out c8);
		ulong c10 = MultiplyAdd(x5, x4, c9, 0, out c9);
		ulong h0 = Multiply(x0, x0, out t0);
		ulong h1 = Multiply(x1, x1, out ulong l1);
		ulong h2 = Multiply(x2, x2, out ulong l2);
		ulong h3 = Multiply(x3, x3, out ulong l3);
		ulong h4 = Multiply(x4, x4, out ulong l4);
		ulong h5 = Multiply(x5, x5, out ulong l5);
		carry = 0;
		t1 = AddWithCarry(c1 << 1, h0, ref carry);
		t2 = AddWithCarry(c2 << 1 | c1 >> 63, l1, ref carry);
		t3 = AddWithCarry(c3 << 1 | c2 >> 63, h1, ref carry);
		t4 = AddWithCarry(c4 << 1 | c3 >> 63, l2, ref carry);
		t5 = AddWithCarry(c5 << 1 | c4 >> 63, h2, ref carry);
		t6 = AddWithCarry(c6 << 1 | c5 >> 63, l3, ref carry);
		t7 = AddWithCarry(c7 << 1 | c6 >> 63, h3, ref carry);
		t8 = AddWithCarry(c8 << 1 | c7 >> 63, l4, ref carry);
		t9 = AddWithCarry(c9 << 1 | c8 >> 63, h4, ref carry);
		t10 = AddWithCarry(c10 << 1 | c9 >> 63, l5, ref carry);
		// x² is below 2^768, so the top limb does not wrap.
		t11 = (c10 >> 63) + h5 + carry;
	}

	// Returns the 64 bits from position on, with zeros above the top limb. Only position decides which limbs are read.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong ReadBits(ReadOnlySpan<ulong> limbs, int position)
	{
		int index = position >> 6;
		int shift = position & 63;
		ulong low = index < limbs.Length ? limbs[index] : 0;
		ulong high = index + 1 < limbs.Length ? limbs[index + 1] : 0;
		// high << 1 << 63 - shift is high << 64 - shift, which is 0 when shift = 0.
		return low >> shift | high << 1 << 63 - shift;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong Select(ulong mask, ulong whenSet, ulong whenClear)
	{
		return whenClear ^ (whenClear ^ whenSet) & mask;
	}
}
