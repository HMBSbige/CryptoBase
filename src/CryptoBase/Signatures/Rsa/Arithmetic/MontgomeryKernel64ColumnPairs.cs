using CryptoBase.EllipticCurves;

namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The representation and the sums of MontgomeryKernel64, with the columns taken in pairs (c, c + 1) from c = 0: a_i and m_i are read once for both columns, and the digit of b or n that column c + 1 takes at i is the one that column c took at i − 1, so that a product needs one read.
// The sums of a pair start at zero and take the carry into column c after the products, so that the products of a pair need not wait for the reduction of the pair before; its two reduction digits come one after the other at its end. When digitCount is odd, the pair across it goes column by column.
// A square takes the cross products a_i·a_j for i < j once and doubles them, as MontgomeryKernel64 does.
// The products pass the radix to their helpers as locals (see IRadix).
internal readonly struct MontgomeryKernel64ColumnPairs<TRadix> : IMontgomeryKernel where TRadix : struct, IRadix
{
	private static int Shift => 64 - TRadix.Bits;

	public static bool IsSupported => Bmi2.X64.IsSupported || ArmBase.Arm64.IsSupported;

	public static int DigitBits => TRadix.Bits;

	public static int MaxDigitCount => (1 << 63 - TRadix.Bits) - 2;

	// The shifted copy of the right operand and the digits m_k.
	public static int GetScratchLength(int digitCount)
	{
		return 2 * digitCount;
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		Debug.Assert(prepared.Length == modulus.Length);

		for (int i = 0; i < modulus.Length; ++i)
		{
			prepared[i] = modulus[i] << Shift;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int bits = TRadix.Bits;
		int shift = 64 - bits;
		ulong mask = (1UL << bits) - 1;
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
		ulong carryLow = 0;
		ulong carryHigh = 0;
		ulong product;
		nint c = 0;

		// Pairs below digits: i from 0 to c − 1 for both products, then a·b alone for i = c and c + 1, as m_c and m_(c+1) come at the end of the pair.
		for (; c + 1 < digits; c += 2)
		{
			ulong low0 = 0, high0 = 0, low1 = 0, high1 = 0, reductionLow0 = 0, reductionHigh0 = 0, reductionLow1 = 0, reductionHigh1 = 0;
			ref ulong x = ref a;
			ref ulong u = ref m;
			ref ulong y = ref Unsafe.Add(ref b, c);
			ref ulong v = ref Unsafe.Add(ref n, c);
			ulong yNext = Unsafe.Add(ref b, c + 1);
			ulong vNext = Unsafe.Add(ref n, c + 1);
			nint count = c;

			for (; count >= 2; count -= 2)
			{
				ulong x0 = x;
				ulong u0 = u;
				ulong y0 = y;
				ulong v0 = v;
				high0 += LimbArithmetic.Multiply(x0, y0, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x0, yNext, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u0, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u0, vNext, out product);
				reductionLow1 += product >> shift;
				ulong x1 = Unsafe.Add(ref x, 1);
				ulong u1 = Unsafe.Add(ref u, 1);
				yNext = Unsafe.Subtract(ref y, 1);
				vNext = Unsafe.Subtract(ref v, 1);
				high0 += LimbArithmetic.Multiply(x1, yNext, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x1, y0, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u1, vNext, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u1, v0, out product);
				reductionLow1 += product >> shift;
				x = ref Unsafe.Add(ref x, 2);
				u = ref Unsafe.Add(ref u, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (count > 0)
			{
				high0 += LimbArithmetic.Multiply(x, y, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x, yNext, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u, v, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u, vNext, out product);
				reductionLow1 += product >> shift;
			}

			ulong first = Unsafe.Add(ref a, c);
			high0 += LimbArithmetic.Multiply(first, b, out product);
			low0 += product >> shift;
			high1 += LimbArithmetic.Multiply(first, Unsafe.Add(ref b, 1), out product);
			low1 += product >> shift;
			high1 += LimbArithmetic.Multiply(Unsafe.Add(ref a, c + 1), b, out product);
			low1 += product >> shift;
			(carryLow, carryHigh) = ReducePair(ref n, ref m, c, low0 + reductionLow0 + carryLow, high0 + reductionHigh0 + carryHigh, low1 + reductionLow1, high1 + reductionHigh1, negativeInverse, bits, shift, mask);
		}

		if (c < digits)
		{
			(carryLow, carryHigh) = MultiplyColumn(ref a, ref b, ref n, ref m, ref output, c, digits, negativeInverse, carryLow, carryHigh, bits, shift, mask);
			(carryLow, carryHigh) = MultiplyColumn(ref a, ref b, ref n, ref m, ref output, c + 1, digits, negativeInverse, carryLow, carryHigh, bits, shift, mask);
			c += 2;
		}

		// Pairs of the result: column c has i from first = c − digits + 1 to digits − 1, column c + 1 from first + 1.
		for (; c < 2 * digits; c += 2)
		{
			nint first = c - digits + 1;
			ulong low0 = 0, high0 = 0, low1 = 0, high1 = 0, reductionLow0 = 0, reductionHigh0 = 0, reductionLow1 = 0, reductionHigh1 = 0;
			ulong yNext = Unsafe.Add(ref b, digits - 1);
			ulong vNext = Unsafe.Add(ref n, digits - 1);
			high0 += LimbArithmetic.Multiply(Unsafe.Add(ref a, first), yNext, out product);
			low0 += product >> shift;
			reductionHigh0 += LimbArithmetic.Multiply(Unsafe.Add(ref m, first), vNext, out product);
			reductionLow0 += product >> shift;
			ref ulong x = ref Unsafe.Add(ref a, first + 1);
			ref ulong u = ref Unsafe.Add(ref m, first + 1);
			ref ulong y = ref Unsafe.Add(ref b, digits - 2);
			ref ulong v = ref Unsafe.Add(ref n, digits - 2);
			nint count = digits - 1 - first;

			for (; count >= 2; count -= 2)
			{
				ulong x0 = x;
				ulong u0 = u;
				ulong y0 = y;
				ulong v0 = v;
				high0 += LimbArithmetic.Multiply(x0, y0, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x0, yNext, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u0, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u0, vNext, out product);
				reductionLow1 += product >> shift;
				ulong x1 = Unsafe.Add(ref x, 1);
				ulong u1 = Unsafe.Add(ref u, 1);
				yNext = Unsafe.Subtract(ref y, 1);
				vNext = Unsafe.Subtract(ref v, 1);
				high0 += LimbArithmetic.Multiply(x1, yNext, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x1, y0, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u1, vNext, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u1, v0, out product);
				reductionLow1 += product >> shift;
				x = ref Unsafe.Add(ref x, 2);
				u = ref Unsafe.Add(ref u, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (count > 0)
			{
				high0 += LimbArithmetic.Multiply(x, y, out product);
				low0 += product >> shift;
				high1 += LimbArithmetic.Multiply(x, yNext, out product);
				low1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u, v, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u, vNext, out product);
				reductionLow1 += product >> shift;
			}

			(carryLow, carryHigh) = OutputPair(ref output, c - digits, low0 + reductionLow0 + carryLow, high0 + reductionHigh0 + carryHigh, low1 + reductionLow1, high1 + reductionHigh1, bits, mask);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int bits = TRadix.Bits;
		int shift = 64 - bits;
		ulong mask = (1UL << bits) - 1;
		nint digits = modulus.Length;

		Debug.Assert(result.Length == digits && value.Length == digits && scratch.Length >= 2 * digits);

		ref ulong a = ref MemoryMarshal.GetReference(value);
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong b = ref MemoryMarshal.GetReference(scratch);
		ref ulong m = ref Unsafe.Add(ref b, digits);

		for (nint j = 0; j < digits; ++j)
		{
			Unsafe.Add(ref b, j) = Unsafe.Add(ref a, j) << shift;
		}

		ref ulong output = ref MemoryMarshal.GetReference(result);
		ulong carryLow = 0;
		ulong carryHigh = 0;
		ulong product;
		nint c = 0;

		// Pairs below digits: cross products for i below half = c/2 in both columns, with the products of m and n, which go on alone to c − 1; then a_half·a_(half+1) for column c + 1 and a_half² for column c.
		for (; c + 1 < digits; c += 2)
		{
			nint half = c >> 1;
			ulong crossLow0 = 0, crossHigh0 = 0, crossLow1 = 0, crossHigh1 = 0, reductionLow0 = 0, reductionHigh0 = 0, reductionLow1 = 0, reductionHigh1 = 0;
			ref ulong x = ref a;
			ref ulong u = ref m;
			ref ulong y = ref Unsafe.Add(ref b, c);
			ref ulong v = ref Unsafe.Add(ref n, c);
			ulong yNext = Unsafe.Add(ref b, c + 1);
			ulong vNext = Unsafe.Add(ref n, c + 1);
			nint i = 0;

			for (; i + 2 <= half; i += 2)
			{
				ulong x0 = x;
				ulong u0 = u;
				ulong y0 = y;
				ulong v0 = v;
				crossHigh0 += LimbArithmetic.Multiply(x0, y0, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x0, yNext, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u0, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u0, vNext, out product);
				reductionLow1 += product >> shift;
				ulong x1 = Unsafe.Add(ref x, 1);
				ulong u1 = Unsafe.Add(ref u, 1);
				yNext = Unsafe.Subtract(ref y, 1);
				vNext = Unsafe.Subtract(ref v, 1);
				crossHigh0 += LimbArithmetic.Multiply(x1, yNext, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x1, y0, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u1, vNext, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u1, v0, out product);
				reductionLow1 += product >> shift;
				x = ref Unsafe.Add(ref x, 2);
				u = ref Unsafe.Add(ref u, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (i < half)
			{
				ulong y0 = y;
				ulong v0 = v;
				crossHigh0 += LimbArithmetic.Multiply(x, y0, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x, yNext, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u, vNext, out product);
				reductionLow1 += product >> shift;
				vNext = v0;
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
				++i;
			}

			(reductionLow0, reductionHigh0, reductionLow1, reductionHigh1) = AccumulateReduction(ref u, ref v, vNext, c - i, reductionLow0, reductionHigh0, reductionLow1, reductionHigh1, shift);
			ulong middle = Unsafe.Add(ref a, half);
			crossHigh1 += LimbArithmetic.Multiply(middle, Unsafe.Add(ref b, half + 1), out product);
			crossLow1 += product >> shift;
			ulong low0 = (crossLow0 << 1) + reductionLow0 + carryLow;
			ulong high0 = (crossHigh0 << 1) + reductionHigh0 + carryHigh;
			high0 += LimbArithmetic.Multiply(middle, Unsafe.Add(ref b, half), out product);
			low0 += product >> shift;
			(carryLow, carryHigh) = ReducePair(ref n, ref m, c, low0, high0, (crossLow1 << 1) + reductionLow1, (crossHigh1 << 1) + reductionHigh1, negativeInverse, bits, shift, mask);
		}

		if (c < digits)
		{
			(carryLow, carryHigh) = SquareColumn(ref a, ref b, ref n, ref m, ref output, c, digits, negativeInverse, carryLow, carryHigh, bits, shift, mask);
			(carryLow, carryHigh) = SquareColumn(ref a, ref b, ref n, ref m, ref output, c + 1, digits, negativeInverse, carryLow, carryHigh, bits, shift, mask);
			c += 2;
		}

		// Pairs of the result: column c has cross products from first = c − digits + 1 to half − 1 and a_half², column c + 1 from first + 1 to half; the products of m and n run from first and first + 1 to digits − 1.
		for (; c < 2 * digits; c += 2)
		{
			nint half = c >> 1;
			nint first = c - digits + 1;
			ulong crossLow0 = 0, crossHigh0 = 0, crossLow1 = 0, crossHigh1 = 0, reductionLow0 = 0, reductionHigh0 = 0, reductionLow1 = 0, reductionHigh1 = 0;
			ulong yNext = Unsafe.Add(ref b, digits - 1);
			ulong vNext = Unsafe.Add(ref n, digits - 1);

			if (first < half)
			{
				crossHigh0 += LimbArithmetic.Multiply(Unsafe.Add(ref a, first), yNext, out product);
				crossLow0 += product >> shift;
			}

			reductionHigh0 += LimbArithmetic.Multiply(Unsafe.Add(ref m, first), vNext, out product);
			reductionLow0 += product >> shift;
			ref ulong x = ref Unsafe.Add(ref a, first + 1);
			ref ulong u = ref Unsafe.Add(ref m, first + 1);
			ref ulong y = ref Unsafe.Add(ref b, digits - 2);
			ref ulong v = ref Unsafe.Add(ref n, digits - 2);
			nint i = first + 1;

			for (; i + 2 <= half; i += 2)
			{
				ulong x0 = x;
				ulong u0 = u;
				ulong y0 = y;
				ulong v0 = v;
				crossHigh0 += LimbArithmetic.Multiply(x0, y0, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x0, yNext, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u0, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u0, vNext, out product);
				reductionLow1 += product >> shift;
				ulong x1 = Unsafe.Add(ref x, 1);
				ulong u1 = Unsafe.Add(ref u, 1);
				yNext = Unsafe.Subtract(ref y, 1);
				vNext = Unsafe.Subtract(ref v, 1);
				crossHigh0 += LimbArithmetic.Multiply(x1, yNext, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x1, y0, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u1, vNext, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u1, v0, out product);
				reductionLow1 += product >> shift;
				x = ref Unsafe.Add(ref x, 2);
				u = ref Unsafe.Add(ref u, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (i < half)
			{
				ulong y0 = y;
				ulong v0 = v;
				crossHigh0 += LimbArithmetic.Multiply(x, y0, out product);
				crossLow0 += product >> shift;
				crossHigh1 += LimbArithmetic.Multiply(x, yNext, out product);
				crossLow1 += product >> shift;
				reductionHigh0 += LimbArithmetic.Multiply(u, v0, out product);
				reductionLow0 += product >> shift;
				reductionHigh1 += LimbArithmetic.Multiply(u, vNext, out product);
				reductionLow1 += product >> shift;
				vNext = v0;
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
				++i;
			}

			(reductionLow0, reductionHigh0, reductionLow1, reductionHigh1) = AccumulateReduction(ref u, ref v, vNext, digits - i, reductionLow0, reductionHigh0, reductionLow1, reductionHigh1, shift);
			ulong middle = Unsafe.Add(ref a, half);

			if (half + 1 < digits)
			{
				crossHigh1 += LimbArithmetic.Multiply(middle, Unsafe.Add(ref b, half + 1), out product);
				crossLow1 += product >> shift;
			}

			ulong low0 = (crossLow0 << 1) + reductionLow0 + carryLow;
			ulong high0 = (crossHigh0 << 1) + reductionHigh0 + carryHigh;
			high0 += LimbArithmetic.Multiply(middle, Unsafe.Add(ref b, half), out product);
			low0 += product >> shift;
			(carryLow, carryHigh) = OutputPair(ref output, c - digits, low0, high0, (crossLow1 << 1) + reductionLow1, (crossHigh1 << 1) + reductionHigh1, bits, mask);
		}
	}

	// Adds m_i·n_(c−i) to the sums of column c and m_i·n_(c+1−i) to those of column c + 1 for count values of i from the one that u points at, with v at n_(c−i) and next = n_(c+1−i).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong, ulong, ulong, ulong) AccumulateReduction(ref ulong u, ref ulong v, ulong next, nint count, ulong low0, ulong high0, ulong low1, ulong high1, int shift)
	{
		ulong product;

		for (; count >= 2; count -= 2)
		{
			ulong u0 = u;
			ulong v0 = v;
			high0 += LimbArithmetic.Multiply(u0, v0, out product);
			low0 += product >> shift;
			high1 += LimbArithmetic.Multiply(u0, next, out product);
			low1 += product >> shift;
			ulong u1 = Unsafe.Add(ref u, 1);
			next = Unsafe.Subtract(ref v, 1);
			high0 += LimbArithmetic.Multiply(u1, next, out product);
			low0 += product >> shift;
			high1 += LimbArithmetic.Multiply(u1, v0, out product);
			low1 += product >> shift;
			u = ref Unsafe.Add(ref u, 2);
			v = ref Unsafe.Subtract(ref v, 2);
		}

		if (count > 0)
		{
			high0 += LimbArithmetic.Multiply(u, v, out product);
			low0 += product >> shift;
			high1 += LimbArithmetic.Multiply(u, next, out product);
			low1 += product >> shift;
		}

		return (low0, high0, low1, high1);
	}

	// Columns c and c + 1 of the reduction from their sums, the carry into column c included: m_c clears the low digit of column c, which passes the rest to column c + 1, and m_(c+1) that of column c + 1. Returns the carry into column c + 2, split as in MontgomeryKernel64.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong Low, ulong High) ReducePair(ref ulong n, ref ulong m, nint c, ulong low0, ulong high0, ulong low1, ulong high1, ulong negativeInverse, int bits, int shift, ulong mask)
	{
		ulong digit = low0 * negativeInverse & mask;
		Unsafe.Add(ref m, c) = digit;
		high0 += LimbArithmetic.Multiply(digit, n, out ulong product);
		low0 += product >> shift;
		high1 += LimbArithmetic.Multiply(digit, Unsafe.Add(ref n, 1), out product);
		low1 += product >> shift;
		low1 += (low0 >> bits) + (high0 & mask);
		high1 += high0 >> bits;
		digit = low1 * negativeInverse & mask;
		Unsafe.Add(ref m, c + 1) = digit;
		high1 += LimbArithmetic.Multiply(digit, n, out product);
		low1 += product >> shift;
		return ((low1 >> bits) + (high1 & mask), high1 >> bits);
	}

	// Digits index and index + 1 of the result from the sums of their columns, the carry into the first included.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static (ulong Low, ulong High) OutputPair(ref ulong output, nint index, ulong low0, ulong high0, ulong low1, ulong high1, int bits, ulong mask)
	{
		Unsafe.Add(ref output, index) = low0 & mask;
		low1 += (low0 >> bits) + (high0 & mask);
		high1 += high0 >> bits;
		Unsafe.Add(ref output, index + 1) = low1 & mask;
		return ((low1 >> bits) + (high1 & mask), high1 >> bits);
	}

	// Column c of a product, which reduces below digits and is a digit of the result from digits on.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static (ulong Low, ulong High) MultiplyColumn(ref ulong a, ref ulong b, ref ulong n, ref ulong m, ref ulong output, nint c, nint digits, ulong negativeInverse, ulong carryLow, ulong carryHigh, int bits, int shift, ulong mask)
	{
		nint first = c < digits ? 0 : c - digits + 1;
		nint last = c < digits ? c : digits - 1;
		ulong low = carryLow;
		ulong high = carryHigh;
		ulong product;

		for (nint i = first; i <= last; ++i)
		{
			high += LimbArithmetic.Multiply(Unsafe.Add(ref a, i), Unsafe.Add(ref b, c - i), out product);
			low += product >> shift;
		}

		for (nint i = first; i < (c < digits ? c : digits); ++i)
		{
			high += LimbArithmetic.Multiply(Unsafe.Add(ref m, i), Unsafe.Add(ref n, c - i), out product);
			low += product >> shift;
		}

		return FinishColumn(ref n, ref m, ref output, c, digits, negativeInverse, low, high, bits, shift, mask);
	}

	// Column c of a square, as MultiplyColumn.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static (ulong Low, ulong High) SquareColumn(ref ulong a, ref ulong b, ref ulong n, ref ulong m, ref ulong output, nint c, nint digits, ulong negativeInverse, ulong carryLow, ulong carryHigh, int bits, int shift, ulong mask)
	{
		nint first = c < digits ? 0 : c - digits + 1;
		ulong crossLow = 0;
		ulong crossHigh = 0;
		ulong low = 0;
		ulong high = 0;
		ulong product;

		for (nint i = first; i < c - i; ++i)
		{
			crossHigh += LimbArithmetic.Multiply(Unsafe.Add(ref a, i), Unsafe.Add(ref b, c - i), out product);
			crossLow += product >> shift;
		}

		for (nint i = first; i < (c < digits ? c : digits); ++i)
		{
			high += LimbArithmetic.Multiply(Unsafe.Add(ref m, i), Unsafe.Add(ref n, c - i), out product);
			low += product >> shift;
		}

		low += (crossLow << 1) + carryLow;
		high += (crossHigh << 1) + carryHigh;

		if ((c & 1) is 0)
		{
			high += LimbArithmetic.Multiply(Unsafe.Add(ref a, c >> 1), Unsafe.Add(ref b, c >> 1), out product);
			low += product >> shift;
		}

		return FinishColumn(ref n, ref m, ref output, c, digits, negativeInverse, low, high, bits, shift, mask);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static (ulong Low, ulong High) FinishColumn(ref ulong n, ref ulong m, ref ulong output, nint c, nint digits, ulong negativeInverse, ulong low, ulong high, int bits, int shift, ulong mask)
	{
		if (c < digits)
		{
			ulong digit = low * negativeInverse & mask;
			Unsafe.Add(ref m, c) = digit;
			high += LimbArithmetic.Multiply(digit, n, out ulong product);
			low += product >> shift;
		}
		else
		{
			Unsafe.Add(ref output, c - digits) = low & mask;
		}

		return ((low >> bits) + (high & mask), high >> bits);
	}
}
