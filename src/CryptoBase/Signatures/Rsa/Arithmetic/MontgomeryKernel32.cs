namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Digits of r = TRadix.Bits ≤ 29 bits with a 32 × 32 → 64-bit multiplier, for platforms whose 64-bit multiplier gives no high word: a product of two digits fits a word, and the products of a column, those of the operands and those of m and n on separate sums, add up without carries. At the end of a column the low digits of both sums make its digit, and the rest of both, with the carry of those low digits, the start of the next column, below 3·2^(64−r). A sum then gains at most digitCount + 2 products below 2^(2r), counting the doubled cross products and the diagonal of a square, so that (digitCount + 2)·2^(2r) + 3·2^(64−r) < 2^64 bounds every sum.
// The reduction is interleaved as in MontgomeryKernel64.
internal readonly struct MontgomeryKernel32<TRadix> : IMontgomeryKernel where TRadix : struct, IRadix
{

	public static bool IsSupported => true;

	public static int DigitBits => TRadix.Bits;

	// The largest digitCount with digitCount + 2 < 2^(64−2r) − 3·2^(64−3r), where the second term is below 1 for r ≥ 22.
	public static int MaxDigitCount => (1 << 64 - 2 * TRadix.Bits) - 3;

	// The digits m_k.
	public static int GetScratchLength(int digitCount)
	{
		return digitCount;
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		modulus.CopyTo(prepared);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint digits = modulus.Length;

		Debug.Assert(result.Length == digits && left.Length == digits && right.Length == digits && scratch.Length >= digits);

		ref ulong a = ref MemoryMarshal.GetReference(left);
		ref ulong b = ref MemoryMarshal.GetReference(right);
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong m = ref MemoryMarshal.GetReference(scratch);
		ref ulong output = ref MemoryMarshal.GetReference(result);
		ulong carry = 0;

		for (nint k = 0; k < 2 * digits; ++k)
		{
			nint start = k < digits ? 0 : k - digits + 1;
			nint count = (k < digits ? k : digits) - start;
			ulong sum = carry;
			ulong reduction = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref b, k - start);
			ref ulong u = ref Unsafe.Add(ref m, start);
			ref ulong v = ref Unsafe.Add(ref n, k - start);

			for (; count >= 4; count -= 4)
			{
				sum += Product(x, y);
				reduction += Product(u, v);
				sum += Product(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1));
				reduction += Product(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1));
				sum += Product(Unsafe.Add(ref x, 2), Unsafe.Subtract(ref y, 2));
				reduction += Product(Unsafe.Add(ref u, 2), Unsafe.Subtract(ref v, 2));
				sum += Product(Unsafe.Add(ref x, 3), Unsafe.Subtract(ref y, 3));
				reduction += Product(Unsafe.Add(ref u, 3), Unsafe.Subtract(ref v, 3));
				x = ref Unsafe.Add(ref x, 4);
				y = ref Unsafe.Subtract(ref y, 4);
				u = ref Unsafe.Add(ref u, 4);
				v = ref Unsafe.Subtract(ref v, 4);
			}

			for (; count > 0; --count)
			{
				sum += Product(x, y);
				reduction += Product(u, v);
				x = ref Unsafe.Add(ref x, 1);
				y = ref Unsafe.Subtract(ref y, 1);
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
			}

			if (k < digits)
			{
				sum += Product(Unsafe.Add(ref a, k), b);
				ulong digit = (sum & mask) + (reduction & mask) & mask;
				digit = digit * negativeInverse & mask;
				Unsafe.Add(ref m, k) = digit;
				reduction += Product(digit, n);
			}

			carry = Carry(sum, reduction, out ulong low);

			if (k >= digits)
			{
				Unsafe.Add(ref output, k - digits) = low;
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		nint digits = modulus.Length;

		Debug.Assert(result.Length == digits && value.Length == digits && scratch.Length >= digits);

		ref ulong a = ref MemoryMarshal.GetReference(value);
		ref ulong n = ref MemoryMarshal.GetReference(modulus);
		ref ulong m = ref MemoryMarshal.GetReference(scratch);
		ref ulong output = ref MemoryMarshal.GetReference(result);
		ulong carry = 0;

		for (nint k = 0; k < 2 * digits; ++k)
		{
			nint start = k < digits ? 0 : k - digits + 1;
			nint crossCount = (k + 1 >> 1) - start;
			nint count = (k < digits ? k : digits) - start - crossCount;
			ulong cross = 0;
			ulong reduction = 0;
			ref ulong x = ref Unsafe.Add(ref a, start);
			ref ulong y = ref Unsafe.Add(ref a, k - start);
			ref ulong u = ref Unsafe.Add(ref m, start);
			ref ulong v = ref Unsafe.Add(ref n, k - start);

			for (; crossCount >= 2; crossCount -= 2)
			{
				cross += Product(x, y);
				reduction += Product(u, v);
				cross += Product(Unsafe.Add(ref x, 1), Unsafe.Subtract(ref y, 1));
				reduction += Product(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1));
				x = ref Unsafe.Add(ref x, 2);
				y = ref Unsafe.Subtract(ref y, 2);
				u = ref Unsafe.Add(ref u, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (crossCount > 0)
			{
				cross += Product(x, y);
				reduction += Product(u, v);
				u = ref Unsafe.Add(ref u, 1);
				v = ref Unsafe.Subtract(ref v, 1);
			}

			for (; count >= 2; count -= 2)
			{
				reduction += Product(u, v);
				reduction += Product(Unsafe.Add(ref u, 1), Unsafe.Subtract(ref v, 1));
				u = ref Unsafe.Add(ref u, 2);
				v = ref Unsafe.Subtract(ref v, 2);
			}

			if (count > 0)
			{
				reduction += Product(u, v);
			}

			ulong sum = (cross << 1) + carry;

			if ((k & 1) is 0)
			{
				ulong middle = Unsafe.Add(ref a, k >> 1);
				sum += Product(middle, middle);
			}

			if (k < digits)
			{
				ulong digit = (sum & mask) + (reduction & mask) & mask;
				digit = digit * negativeInverse & mask;
				Unsafe.Add(ref m, k) = digit;
				reduction += Product(digit, n);
			}

			carry = Carry(sum, reduction, out ulong low);

			if (k >= digits)
			{
				Unsafe.Add(ref output, k - digits) = low;
			}
		}
	}

	// A 32 × 32 → 64-bit multiplication, which 32-bit platforms also have.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Product(ulong x, ulong y)
	{
		return Math.BigMul((uint)x, (uint)y);
	}

	// Splits sum + reduction into its low digit and the rest, without forming the sum, which may not fit a word.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Carry(ulong sum, ulong reduction, out ulong low)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		ulong lows = (sum & mask) + (reduction & mask);
		low = lows & mask;
		return (sum >> TRadix.Bits) + (reduction >> TRadix.Bits) + (lows >> TRadix.Bits);
	}
}
