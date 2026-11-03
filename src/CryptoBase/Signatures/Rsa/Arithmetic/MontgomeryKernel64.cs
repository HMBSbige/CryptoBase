using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Digits of r = TRadix.Bits bits with a 64 × 64 → 128-bit multiplier. The second operand of each product is shifted left by s = 64 − r beforehand, so that the high word of the product is its upper digit and the low word shifted right by s its lower digit: a column of the product scanning sums digits without carries. At the end of a column the low sum keeps its low digit, its rest and the low r bits of the high sum go to the next column, and the rest of the high sum to the one after. A column thus starts below 2^(r+1) + 2^(64−r) ≤ 2^(r+2) and adds at most 2·digitCount + 2 digits to the low sum, counting the doubled cross products and the diagonal of a square, so that (2·digitCount + 4)·2^r ≤ 2^64 bounds every sum.
// The reduction is interleaved: column k below digitCount also gains m_k·n, with m_k = sum·(−n⁻¹) mod 2^r, which clears its low digit, and the columns from digitCount on hold the result. The products of the two operands and those of m and n run in the same loop on separate sums, which keeps the chains of additions short.
// A loop of four product pairs, rather than one of each column unrolled in full, keeps the code small and its branches taken; each product is summed right after it is taken, so that its words need no stack.
// From KaratsubaDigits digits on, Karatsuba's method takes the product of the operands from three products of half the size, recursively down to KaratsubaBaseDigits, and the reduction runs in a pass of its own on the product. Its sums of halves are normalized digits again before they are multiplied, so that every product above holds the same bounds.
internal readonly struct MontgomeryKernel64<TRadix> : IMontgomeryKernel where TRadix : struct, IRadix
{
	private const int KaratsubaDigits = 256;
	private const int KaratsubaBaseDigits = 128;

	public static bool IsSupported => Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported;

	public static int DigitBits => TRadix.Bits;

	public static int MaxDigitCount => (1 << 63 - TRadix.Bits) - 2;

	// The shifted copy of the right operand and the digits m_k; with Karatsuba's method, the product of 2·digitCount digits, the digits m_k and what the product needs.
	public static int GetScratchLength(int digitCount)
	{
		return digitCount < KaratsubaDigits ? 2 * digitCount : 3 * digitCount + GetKaratsubaScratchLength(digitCount);
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		int shift = 64 - TRadix.Bits;
		Debug.Assert(prepared.Length == modulus.Length);

		for (int i = 0; i < modulus.Length; ++i)
		{
			prepared[i] = modulus[i] << shift;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int count = modulus.Length;

		if (count >= KaratsubaDigits)
		{
			Span<ulong> product = scratch.Slice(0, 2 * count);
			KaratsubaProduct(product, left, right, scratch.Slice(3 * count));
			Reduce(result, product, modulus, negativeInverse, scratch.Slice(2 * count, count));
			return;
		}

		MultiplyInterleaved(result, left, right, modulus, negativeInverse, scratch);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int count = modulus.Length;

		if (count >= KaratsubaDigits)
		{
			Span<ulong> product = scratch.Slice(0, 2 * count);
			KaratsubaSquare(product, value, scratch.Slice(3 * count));
			Reduce(result, product, modulus, negativeInverse, scratch.Slice(2 * count, count));
			return;
		}

		SquareInterleaved(result, value, modulus, negativeInverse, scratch);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void MultiplyInterleaved(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int shift = 64 - TRadix.Bits;
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint digits = modulus.Length;

		Debug.Assert(result.Length == digits && left.Length == digits && right.Length == digits && scratch.Length >= 2 * digits);

		ref ulong a = ref MemoryMarshal.GetReference(left);
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong b = ref MemoryMarshal.GetReference(scratch);
		ref ulong m = ref Unsafe.Add(ref b, digits);
		ref ulong source = ref MemoryMarshal.GetReference(right);

		for (nint j = 0; j < digits; ++j)
		{
			Unsafe.Add(ref b, j) = Unsafe.Add(ref source, j) << shift;
		}

		ref ulong output = ref MemoryMarshal.GetReference(result);
		ulong carry = 0;
		ulong carryNext = 0;

		for (nint k = 0; k < 2 * digits; ++k)
		{
			nint start = k < digits ? 0 : k - digits + 1;
			nint count = (k < digits ? k : digits) - start;
			ulong low = carry;
			ulong high = carryNext;
			ulong reductionLow = 0;
			ulong reductionHigh = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref b, k - start);
			ref ulong u = ref Unsafe.Add(ref m, start);
			ref ulong v = ref Unsafe.Add(ref n, k - start);

			for (; count >= 4; count -= 4)
			{
				high += LimbArithmetic.Multiply(x, y, out ulong product);
				low += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(u, v, out product);
				reductionLow += product >> shift;
				high += LimbArithmetic.Multiply(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1), out product);
				low += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1), out product);
				reductionLow += product >> shift;
				high += LimbArithmetic.Multiply(Unsafe.Add(ref x, 2), Unsafe.Subtract(ref y, 2), out product);
				low += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 2), Unsafe.Subtract(ref v, 2), out product);
				reductionLow += product >> shift;
				high += LimbArithmetic.Multiply(Unsafe.Add(ref x, 3), Unsafe.Subtract(ref y, 3), out product);
				low += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 3), Unsafe.Subtract(ref v, 3), out product);
				reductionLow += product >> shift;
				x = ref Unsafe.Add(ref x, 4);
				y = ref Unsafe.Subtract(ref y, 4);
				u = ref Unsafe.Add(ref u, 4);
				v = ref Unsafe.Subtract(ref v, 4);
			}

			for (; count > 0; --count)
			{
				high += LimbArithmetic.Multiply(x, y, out ulong product);
				low += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(u, v, out product);
				reductionLow += product >> shift;
				x = ref Unsafe.Add(ref x, 1);
				y = ref Unsafe.Subtract(ref y, 1);
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
			}

			low += reductionLow;
			high += reductionHigh;

			if (k < digits)
			{
				high += LimbArithmetic.Multiply(Unsafe.Add(ref a, k), b, out ulong product);
				low += product >> shift;
				ulong digit = low * negativeInverse & mask;
				Unsafe.Add(ref m, k) = digit;
				high += LimbArithmetic.Multiply(digit, n, out product);
				low += product >> shift;
			}
			else
			{
				Unsafe.Add(ref output, k - digits) = low & mask;
			}

			carry = (low >> TRadix.Bits) + (high & mask);
			carryNext = high >> TRadix.Bits;
		}
	}

	// As MultiplyInterleaved, with the cross products a_i·a_j for i < j taken once and doubled, in the same loop as the products of m and n as far as there are as many of them.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void SquareInterleaved(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int shift = 64 - TRadix.Bits;
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint digits = modulus.Length;

		Debug.Assert(result.Length == digits && value.Length == digits && scratch.Length >= 2 * digits);

		ref ulong a = ref MemoryMarshal.GetReference(value);
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong shifted = ref MemoryMarshal.GetReference(scratch);
		ref ulong m = ref Unsafe.Add(ref shifted, digits);

		for (nint j = 0; j < digits; ++j)
		{
			Unsafe.Add(ref shifted, j) = Unsafe.Add(ref a, j) << shift;
		}

		ref ulong output = ref MemoryMarshal.GetReference(result);
		ulong carry = 0;
		ulong carryNext = 0;

		for (nint k = 0; k < 2 * digits; ++k)
		{
			nint start = k < digits ? 0 : k - digits + 1;
			nint crossCount = (k + 1 >> 1) - start;
			nint count = (k < digits ? k : digits) - start - crossCount;
			ulong crossLow = 0;
			ulong crossHigh = 0;
			ulong reductionLow = 0;
			ulong reductionHigh = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref shifted, k - start);
			ref ulong u = ref Unsafe.Add(ref m, start);
			ref ulong v = ref Unsafe.Add(ref n, k - start);

			for (; crossCount >= 2; crossCount -= 2)
			{
				crossHigh += LimbArithmetic.Multiply(x, y, out ulong product);
				crossLow += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(u, v, out product);
				reductionLow += product >> shift;
				crossHigh += LimbArithmetic.Multiply(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1), out product);
				crossLow += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1), out product);
				reductionLow += product >> shift;
				x = ref Unsafe.Add(ref x, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				u = ref Unsafe.Add(ref u, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (crossCount > 0)
			{
				crossHigh += LimbArithmetic.Multiply(x, y, out ulong product);
				crossLow += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(u, v, out product);
				reductionLow += product >> shift;
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
			}

			for (; count >= 2; count -= 2)
			{
				reductionHigh += LimbArithmetic.Multiply(u, v, out ulong product);
				reductionLow += product >> shift;
				reductionHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1), out product);
				reductionLow += product >> shift;
				u = ref Unsafe.Add(ref u, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (count > 0)
			{
				reductionHigh += LimbArithmetic.Multiply(u, v, out ulong product);
				reductionLow += product >> shift;
			}

			ulong low = (crossLow << 1) + reductionLow + carry;
			ulong high = (crossHigh << 1) + reductionHigh + carryNext;

			if ((k & 1) is 0)
			{
				high += LimbArithmetic.Multiply(Unsafe.Add(ref a, k >> 1), Unsafe.Add(ref shifted, k >> 1), out ulong product);
				low += product >> shift;
			}

			if (k < digits)
			{
				ulong digit = low * negativeInverse & mask;
				Unsafe.Add(ref m, k) = digit;
				high += LimbArithmetic.Multiply(digit, n, out ulong product);
				low += product >> shift;
			}
			else
			{
				Unsafe.Add(ref output, k - digits) = low & mask;
			}

			carry = (low >> TRadix.Bits) + (high & mask);
			carryNext = high >> TRadix.Bits;
		}
	}

	// The scratch of KaratsubaProduct and KaratsubaSquare for operands of count digits: the sums of the halves and the middle product, and what the products of the halves need in turn; a direct product needs a shifted copy of its right operand.
	private static int GetKaratsubaScratchLength(int count)
	{
		if (count < KaratsubaBaseDigits)
		{
			return count;
		}

		int half = (count + 1) / 2;
		return 4 * half + 4 + GetKaratsubaScratchLength(half + 1);
	}

	// product = left·right, of 2·count digits, for normalized operands of count digits.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void KaratsubaProduct(Span<ulong> product, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> scratch)
	{
		int count = left.Length;

		if (count < KaratsubaBaseDigits)
		{
			Product(product.Slice(0, 2 * count), left, right, scratch.Slice(0, count));
			return;
		}

		// left = left1·B^half + left0, and likewise right; the middle product (left0 + left1)(right0 + right1) less the other two is the coefficient of B^half.
		int half = (count + 1) / 2;
		Span<ulong> leftSum = scratch.Slice(0, half + 1);
		Span<ulong> rightSum = scratch.Slice(half + 1, half + 1);
		Span<ulong> middle = scratch.Slice(2 * half + 2, 2 * half + 2);
		Span<ulong> rest = scratch.Slice(4 * half + 4);
		AddHalves(left, half, leftSum);
		AddHalves(right, half, rightSum);
		KaratsubaProduct(product.Slice(0, 2 * half), left.Slice(0, half), right.Slice(0, half), rest);
		KaratsubaProduct(product.Slice(2 * half), left.Slice(half), right.Slice(half), rest);
		KaratsubaProduct(middle, leftSum, rightSum, rest);
		Combine(product, middle, half, count);
	}

	// product = value², as KaratsubaProduct.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void KaratsubaSquare(Span<ulong> product, ReadOnlySpan<ulong> value, Span<ulong> scratch)
	{
		int count = value.Length;

		if (count < KaratsubaBaseDigits)
		{
			ProductSquare(product.Slice(0, 2 * count), value, scratch.Slice(0, count));
			return;
		}

		int half = (count + 1) / 2;
		Span<ulong> sum = scratch.Slice(0, half + 1);
		Span<ulong> middle = scratch.Slice(2 * half + 2, 2 * half + 2);
		Span<ulong> rest = scratch.Slice(4 * half + 4);
		AddHalves(value, half, sum);
		KaratsubaSquare(product.Slice(0, 2 * half), value.Slice(0, half), rest);
		KaratsubaSquare(product.Slice(2 * half), value.Slice(half), rest);
		KaratsubaSquare(middle, sum, rest);
		Combine(product, middle, half, count);
	}

	// sum = value0 + value1, normalized, in half + 1 digits, for value = value1·B^half + value0.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void AddHalves(ReadOnlySpan<ulong> value, int half, Span<ulong> sum)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		ulong carry = 0;

		for (int i = 0; i < half; ++i)
		{
			ulong digit = value[i] + (half + i < value.Length ? value[half + i] : 0) + carry;
			sum[i] = digit & mask;
			carry = digit >> TRadix.Bits;
		}

		sum[half] = carry;
	}

	// Adds middle − low − high at B^half, where the first 2·half digits of product hold low and the rest high, then normalizes the digits, which the differences may leave negative or above the radix.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Combine(Span<ulong> product, Span<ulong> middle, int half, int count)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		for (int i = 0; i < middle.Length; ++i)
		{
			ulong digit = middle[i];

			if (i < 2 * half)
			{
				digit -= product[i];
			}

			if (i < 2 * (count - half))
			{
				digit -= product[2 * half + i];
			}

			middle[i] = digit;
		}

		for (int i = 0; i < middle.Length && half + i < 2 * count; ++i)
		{
			product[half + i] += middle[i];
		}

		long carry = 0;

		for (int i = 0; i < 2 * count; ++i)
		{
			long digit = (long)product[i] + carry;
			product[i] = (ulong)digit & mask;
			carry = digit >> TRadix.Bits;
		}
	}

	// product = left·right by product scanning, with the sums of MultiplyInterleaved and no reduction; product has left.Length + right.Length digits.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Product(Span<ulong> product, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, Span<ulong> shifted)
	{
		int shift = 64 - TRadix.Bits;
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint leftCount = left.Length;
		nint rightCount = right.Length;
		ref ulong a = ref MemoryMarshal.GetReference(left);
		ref ulong b = ref MemoryMarshal.GetReference(shifted);
		ref ulong source = ref MemoryMarshal.GetReference(right);
		ref ulong output = ref MemoryMarshal.GetReference(product);

		for (nint j = 0; j < rightCount; ++j)
		{
			Unsafe.Add(ref b, j) = Unsafe.Add(ref source, j) << shift;
		}

		ulong carry = 0;
		ulong carryNext = 0;

		for (nint k = 0; k < leftCount + rightCount - 1; ++k)
		{
			nint start = k < rightCount ? 0 : k - rightCount + 1;
			nint count = (k < leftCount ? k + 1 : leftCount) - start;
			ulong low = carry;
			ulong high = carryNext;
			ulong otherLow = 0;
			ulong otherHigh = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref b, k - start);

			for (; count >= 4; count -= 4)
			{
				high += LimbArithmetic.Multiply(x, y, out ulong term);
				low += term >> shift;
				otherHigh += LimbArithmetic.Multiply(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1), out term);
				otherLow += term >> shift;
				high += LimbArithmetic.Multiply(Unsafe.Add(ref x, 2), Unsafe.Subtract(ref y, 2), out term);
				low += term >> shift;
				otherHigh += LimbArithmetic.Multiply(Unsafe.Add(ref x, 3), Unsafe.Subtract(ref y, 3), out term);
				otherLow += term >> shift;
				x = ref Unsafe.Add(ref x, 4);
				y = ref Unsafe.Subtract(ref y, 4);
			}

			for (; count > 0; --count)
			{
				high += LimbArithmetic.Multiply(x, y, out ulong term);
				low += term >> shift;
				x = ref Unsafe.Add(ref x, 1);
				y = ref Unsafe.Subtract(ref y, 1);
			}

			low += otherLow;
			high += otherHigh;
			Unsafe.Add(ref output, k) = low & mask;
			carry = (low >> TRadix.Bits) + (high & mask);
			carryNext = high >> TRadix.Bits;
		}

		Unsafe.Add(ref output, leftCount + rightCount - 1) = carry + (carryNext << TRadix.Bits);
	}

	// product = value² by product scanning, with the doubled cross products of SquareInterleaved and no reduction.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void ProductSquare(Span<ulong> product, ReadOnlySpan<ulong> value, Span<ulong> shifted)
	{
		int shift = 64 - TRadix.Bits;
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint count = value.Length;
		ref ulong a = ref MemoryMarshal.GetReference(value);
		ref ulong b = ref MemoryMarshal.GetReference(shifted);
		ref ulong output = ref MemoryMarshal.GetReference(product);

		for (nint j = 0; j < count; ++j)
		{
			Unsafe.Add(ref b, j) = Unsafe.Add(ref a, j) << shift;
		}

		ulong carry = 0;
		ulong carryNext = 0;

		for (nint k = 0; k < 2 * count - 1; ++k)
		{
			nint start = k < count ? 0 : k - count + 1;
			nint crossCount = (k + 1 >> 1) - start;
			ulong crossLow = 0;
			ulong crossHigh = 0;
			ulong otherLow = 0;
			ulong otherHigh = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref b, k - start);

			for (; crossCount >= 2; crossCount -= 2)
			{
				crossHigh += LimbArithmetic.Multiply(x, y, out ulong term);
				crossLow += term >> shift;
				otherHigh += LimbArithmetic.Multiply(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1), out term);
				otherLow += term >> shift;
				x = ref Unsafe.Add(ref x, 2);
				y = ref Unsafe.Subtract(ref y, 2);
			}

			if (crossCount > 0)
			{
				crossHigh += LimbArithmetic.Multiply(x, y, out ulong term);
				crossLow += term >> shift;
			}

			ulong low = (crossLow + otherLow << 1) + carry;
			ulong high = (crossHigh + otherHigh << 1) + carryNext;

			if ((k & 1) is 0)
			{
				high += LimbArithmetic.Multiply(Unsafe.Add(ref a, k >> 1), Unsafe.Add(ref b, k >> 1), out ulong term);
				low += term >> shift;
			}

			Unsafe.Add(ref output, k) = low & mask;
			carry = (low >> TRadix.Bits) + (high & mask);
			carryNext = high >> TRadix.Bits;
		}

		Unsafe.Add(ref output, 2 * count - 1) = carry + (carryNext << TRadix.Bits);
	}

	// result = product·R⁻¹ mod n, below 2n, by the reduction of MultiplyInterleaved alone, on a product of 2·count normalized digits.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Reduce(Span<ulong> result, ReadOnlySpan<ulong> product, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> digits)
	{
		int shift = 64 - TRadix.Bits;
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint count = modulus.Length;
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong m = ref MemoryMarshal.GetReference(digits);
		ref ulong output = ref MemoryMarshal.GetReference(result);
		ref ulong input = ref MemoryMarshal.GetReference(product);
		ulong carry = 0;
		ulong carryNext = 0;

		for (nint k = 0; k < 2 * count; ++k)
		{
			nint start = k < count ? 0 : k - count + 1;
			nint remaining = (k < count ? k : count) - start;
			ulong low = carry + Unsafe.Add(ref input, k);
			ulong high = carryNext;
			ulong otherLow = 0;
			ulong otherHigh = 0;
			ref ulong u = ref Unsafe.Add(ref m, start);
			ref ulong v = ref Unsafe.Add(ref n, k - start);

			for (; remaining >= 4; remaining -= 4)
			{
				high += LimbArithmetic.Multiply(u, v, out ulong term);
				low += term >> shift;
				otherHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1), out term);
				otherLow += term >> shift;
				high += LimbArithmetic.Multiply(Unsafe.Add(ref u, 2), Unsafe.Subtract(ref v, 2), out term);
				low += term >> shift;
				otherHigh += LimbArithmetic.Multiply(Unsafe.Add(ref u, 3), Unsafe.Subtract(ref v, 3), out term);
				otherLow += term >> shift;
				u = ref Unsafe.Add(ref u, 4);
				v = ref Unsafe.Subtract(ref v, 4);
			}

			for (; remaining > 0; --remaining)
			{
				high += LimbArithmetic.Multiply(u, v, out ulong term);
				low += term >> shift;
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
			}

			low += otherLow;
			high += otherHigh;

			if (k < count)
			{
				ulong digit = low * negativeInverse & mask;
				Unsafe.Add(ref m, k) = digit;
				high += LimbArithmetic.Multiply(digit, n, out ulong term);
				low += term >> shift;
			}
			else
			{
				Unsafe.Add(ref output, k - count) = low & mask;
			}

			carry = (low >> TRadix.Bits) + (high & mask);
			carryNext = high >> TRadix.Bits;
		}
	}
}
