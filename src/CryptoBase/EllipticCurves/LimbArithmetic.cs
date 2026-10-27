namespace CryptoBase.EllipticCurves;

// Carries and borrows are 0 or 1. A comparison taken as a value, as in Carry, compiles to a flag read such as setb or cset and not to a branch. The methods on limb sequences take count limbs, least significant first, and are unrolled up to MaxLimbCount so that a constant count drops the steps beyond it. A result may be the same sequence as an input unless a method says otherwise.
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

		return MultiplyPortable(x, y, out low);
	}

	// Without BMI2 or Arm64, Math.BigMul calls a fallback that passes the low limb through memory; the same four 32-bit products inlined need neither the call nor the memory. They are kept out of Multiply, whose IL counts against the inlining budget of every caller, so that it stays small.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong MultiplyPortable(ulong x, ulong y, out ulong low)
	{
		ulong xLow = (uint)x;
		ulong xHigh = x >> 32;
		ulong yLow = (uint)y;
		ulong yHigh = y >> 32;
		ulong lowProduct = xLow * yLow;
		ulong cross1 = xHigh * yLow;
		ulong cross2 = xLow * yHigh;
		// Below 3·2^32, so it does not wrap.
		ulong middle = (lowProduct >> 32) + (uint)cross1 + (uint)cross2;
		low = middle << 32 | (uint)lowProduct;
		return xHigh * yHigh + (cross1 >> 32) + (cross2 >> 32) + (middle >> 32);
	}

	// As Multiply, but without BMI2 or Arm64 a call to Math.BigMul, for code with many products at once, such as the matrix steps of SafeGcd, where the inlined portable products would leave so many values live that most of them would spill.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong MultiplyOutOfLine(ulong x, ulong y, out ulong low)
	{
		if (Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported)
		{
			return Multiply(x, y, out low);
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
