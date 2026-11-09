namespace CryptoBase.Signatures.Rsa.Arithmetic;

// Digits of r ≤ 28 bits with umlal2, which adds 32 × 32 → 64-bit products to 64-bit lanes. Each operation narrows its operands to 32-bit words with Pad zeros on either side, so that a read past an end gives zeros and no column checks its bounds.
// Product scanning in blocks of four columns: by element, lane c of a block gains a_i·b_(c−i) for each i at once. umlal2 takes the upper half of a quad, so lanes 2 and 3 of the block take the quad of b at k − i and lanes 0 and 1 the quad two words lower; no lower half is copied out of a register, and consecutive groups of four i share two of the quads they load. Sixteen sums, for each half of the block, operand pair and i mod 4, cover the latency of umlal.
// A column sums at most 2·digitCount products below 2^(2r) and a carry below 2^(64−r), which bounds digitCount by 2^(63−2r).
// The reduction digits of a block come one after another at its end, a column per register in lane 0, each passing its carry to the next with usra. The sums of a block start at zero and take the carry out of the block before only in its tail, so that the products of a block need not wait for the reduction of the one before. Columns from digitCount on hold the result; the block across digitCount, when digitCount is not a multiple of 4, goes column by column.
// A square takes each cross product once, from a doubled copy of the operand, with the products around the diagonal in one group.
// A load across a page boundary is far slower than one within a page, and the blocks load b and n at every word: each operand starts on 16 bytes, within a page where one holds it, wherever the scratch lies.
// The tails take the mask of a digit from the products (see IRadix).
internal readonly struct MontgomeryKernelAdvSimd<TRadix> : IMontgomeryKernel where TRadix : struct, IRadix
{
	// Words of zeros on either side of each operand, more than the seven that a block reads past the ends.
	private const int Pad = 8;

	// 4 KB, the smallest page of the platforms, whose boundaries are also those of larger pages.
	private const nuint PageMask = 4095;

	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	public static int DigitBits => TRadix.Bits;

	public static int MaxDigitCount => 1 << 63 - 2 * TRadix.Bits;

	// Four operands of digitCount words with their zeros, a, b and n with the digits m for a product, and a, 2·a, n and m for a square, each of which Place may move by as much as it takes and 15 bytes.
	public static int GetScratchLength(int digitCount)
	{
		return 4 * (digitCount + 2 * Pad) + 8;
	}

	public static void Prepare(ReadOnlySpan<ulong> modulus, Span<ulong> prepared)
	{
		modulus.CopyTo(prepared);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Multiply(Span<ulong> result, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int digits = modulus.Length;

		Debug.Assert(result.Length == digits && left.Length == digits && right.Length == digits && scratch.Length >= GetScratchLength(digits));

		int stride = digits + 2 * Pad;
		ref uint a = ref Place(ref Unsafe.As<ulong, uint>(ref MemoryMarshal.GetReference(scratch)), stride, Pad);
		ref uint b = ref Place(ref Unsafe.Add(ref a, stride - Pad), stride, Pad);
		ref uint n = ref Place(ref Unsafe.Add(ref b, stride - Pad), stride, Pad);
		ref uint m = ref Place(ref Unsafe.Add(ref n, stride - Pad), stride, Pad);
		Narrow(left, ref a, 0);
		Narrow(right, ref b, 0);
		Narrow(modulus, ref n, 0);
		ClearPad(ref Unsafe.Add(ref m, digits));
		MultiplyCore(result, ref a, ref b, ref n, ref m, (uint)negativeInverse);
	}

	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Square(Span<ulong> result, ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, ulong negativeInverse, Span<ulong> scratch)
	{
		int digits = modulus.Length;

		Debug.Assert(result.Length == digits && value.Length == digits && scratch.Length >= GetScratchLength(digits));

		int stride = digits + 2 * Pad;
		ref uint a = ref Place(ref Unsafe.As<ulong, uint>(ref MemoryMarshal.GetReference(scratch)), stride, Pad);
		ref uint twice = ref Place(ref Unsafe.Add(ref a, stride - Pad), stride, Pad);
		ref uint n = ref Place(ref Unsafe.Add(ref twice, stride - Pad), stride, Pad);
		ref uint m = ref Place(ref Unsafe.Add(ref n, stride - Pad), stride, Pad);
		Narrow(value, ref a, 0);
		Narrow(value, ref twice, 1);
		Narrow(modulus, ref n, 0);
		ClearPad(ref Unsafe.Add(ref m, digits));
		SquareCore(result, ref a, ref twice, ref n, ref m, (uint)negativeInverse);
	}

	// The digits of an operand of stride words, zeros included with pad of them before the digits, from the first 16-byte boundary at or after start, or from the page boundary after it where the operand would cross it and a page holds the operand. If the scratch moves meanwhile, only the speed changes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe ref uint Place(ref uint start, int stride, int pad)
	{
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		nuint aligned = address + 15 & ~(nuint)15;
		nuint bytes = (nuint)stride * sizeof(uint);
		nuint boundary = (aligned | PageMask) + 1;
		nuint placed = aligned + bytes > boundary && bytes <= PageMask + 1 ? boundary : aligned;
		return ref Unsafe.Add(ref Unsafe.AddByteOffset(ref start, placed - address), pad);
	}

	// The digits as words shifted left by shift, with Pad zeros on either side.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void Narrow(ReadOnlySpan<ulong> digits, ref uint words, int shift)
	{
		ref ulong source = ref MemoryMarshal.GetReference(digits);
		int i = 0;

		for (; i + 4 <= digits.Length; i += 4)
		{
			Vector128<uint> quad = Vector128.Narrow(Vector128.LoadUnsafe(ref source, (nuint)i), Vector128.LoadUnsafe(ref source, (nuint)i + 2));
			(quad << shift).StoreUnsafe(ref words, (nuint)i);
		}

		for (; i < digits.Length; ++i)
		{
			Unsafe.Add(ref words, i) = (uint)Unsafe.Add(ref source, i) << shift;
		}

		ClearPad(ref Unsafe.Subtract(ref words, Pad));
		ClearPad(ref Unsafe.Add(ref words, digits.Length));
	}

	private static void ClearPad(ref uint start)
	{
		Vector128<uint>.Zero.StoreUnsafe(ref start);
		Vector128<uint>.Zero.StoreUnsafe(ref start, 4);
	}

	// Block k has the columns k to k + 3 of a·b + m·n. Below digitCount it takes i from 0 to k − 1 for both products and k to k + 3 for a·b alone, whose digits m the tail finds; from digitCount on, i from k − digitCount + 1 to digitCount − 1, rounded down to a multiple of 4, which the zeros allow.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void MultiplyCore(Span<ulong> result, ref uint a, ref uint b, ref uint n, ref uint m, uint negativeInverse)
	{
		nint count = result.Length;
		ulong mask = (1UL << TRadix.Bits) - 1;
		ref ulong output = ref MemoryMarshal.GetReference(result);
		Vector128<uint> inverse = Vector128.Create(negativeInverse);
		Vector128<ulong> carry = Vector128<ulong>.Zero;

		for (nint k = 0; k < 2 * count; k += 4)
		{
			Vector128<ulong> ab01e = default, ab23e = default, ab01f = default, ab23f = default, ab01g = default, ab23g = default, ab01h = default, ab23h = default;
			Vector128<ulong> mn01e = default, mn23e = default, mn01f = default, mn23f = default, mn01g = default, mn23g = default, mn01h = default, mn23h = default;
			nint start = k < count ? 0 : k - count + 1 & ~3;
			nint end = k < count ? k : count;
			ref uint x = ref Unsafe.Add(ref a, start);
			ref uint u = ref Unsafe.Add(ref m, start);
			ref uint y = ref Unsafe.Add(ref b, k - start);
			ref uint v = ref Unsafe.Add(ref n, k - start);
			Vector128<uint> y0 = Vector128.LoadUnsafe(ref y);
			Vector128<uint> y1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 1));
			Vector128<uint> v0 = Vector128.LoadUnsafe(ref v);
			Vector128<uint> v1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 1));

			// y and v point at the words k − i of b and n; y0, y1, v0 and v1 hold the quads there and one below.
			for (nint g = start; g < end; g += 4)
			{
				Vector128<uint> ax = Vector128.LoadUnsafe(ref x);
				Vector128<uint> mx = Vector128.LoadUnsafe(ref u);
				Vector128<uint> y2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 2));
				Vector128<uint> v2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 2));
				ab23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23e, y0, ax, 0);
				mn23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23e, v0, mx, 0);
				ab01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01e, y2, ax, 0);
				mn01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01e, v2, mx, 0);
				Vector128<uint> y3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 3));
				Vector128<uint> v3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 3));
				ab23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23f, y1, ax, 1);
				mn23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23f, v1, mx, 1);
				ab01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01f, y3, ax, 1);
				mn01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01f, v3, mx, 1);
				y0 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 4));
				v0 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 4));
				ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, y2, ax, 2);
				mn23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23g, v2, mx, 2);
				ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, y0, ax, 2);
				mn01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01g, v0, mx, 2);
				y1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 5));
				v1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 5));
				ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, y3, ax, 3);
				mn23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23h, v3, mx, 3);
				ab01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01h, y1, ax, 3);
				mn01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01h, v1, mx, 3);
				x = ref Unsafe.Add(ref x, 4);
				u = ref Unsafe.Add(ref u, 4);
				y = ref Unsafe.Subtract(ref y, 4);
				v = ref Unsafe.Subtract(ref v, 4);
			}

			if (k < count)
			{
				// i from k to k + 3, where y points at the word 0 of b.
				Vector128<uint> ax = Vector128.LoadUnsafe(ref x);
				Vector128<uint> y2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 2));
				Vector128<uint> y3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 3));
				Vector128<uint> y4 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 4));
				Vector128<uint> y5 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 5));
				ab23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23e, y0, ax, 0);
				ab01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01e, y2, ax, 0);
				ab23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23f, y1, ax, 1);
				ab01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01f, y3, ax, 1);
				ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, y2, ax, 2);
				ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, y4, ax, 2);
				ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, y3, ax, 3);
				ab01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01h, y5, ax, 3);
			}

			Vector128<ulong> low = ab01e + ab01f + (ab01g + ab01h) + (mn01e + mn01f + (mn01g + mn01h));
			Vector128<ulong> high = ab23e + ab23f + (ab23g + ab23h) + (mn23e + mn23f + (mn23g + mn23h));
			carry = Tail(low, high, carry, ref n, ref m, ref output, k, count, inverse, mask);
		}
	}

	// As MultiplyCore with b = a: the cross products a_i·a_(c−i) with i below half = k/2, which is below c − i in every lane, come from 2·a with the products of m and n; the group from diagonal = half rounded down to a multiple of 4 then has the products where i reaches half and half + 1, single on the diagonal; m and n go on alone up to the end.
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static void SquareCore(Span<ulong> result, ref uint a, ref uint twice, ref uint n, ref uint m, uint negativeInverse)
	{
		nint count = result.Length;
		ulong mask = (1UL << TRadix.Bits) - 1;
		ref ulong output = ref MemoryMarshal.GetReference(result);
		Vector128<uint> inverse = Vector128.Create(negativeInverse);
		Vector128<uint> thirdLane = Vector128.Create(0, 0, uint.MaxValue, 0);
		Vector128<ulong> carry = Vector128<ulong>.Zero;

		for (nint k = 0; k < 2 * count; k += 4)
		{
			Vector128<ulong> ab01e = default, ab23e = default, ab01f = default, ab23f = default, ab01g = default, ab23g = default, ab01h = default, ab23h = default;
			Vector128<ulong> mn01e = default, mn23e = default, mn01f = default, mn23f = default, mn01g = default, mn23g = default, mn01h = default, mn23h = default;
			nint start = k < count ? 0 : k - count + 1 & ~3;
			nint end = k < count ? k : count;
			nint half = k >> 1;
			nint diagonal = half & ~3;
			ref uint x = ref Unsafe.Add(ref a, start);
			ref uint u = ref Unsafe.Add(ref m, start);
			ref uint y = ref Unsafe.Add(ref twice, k - start);
			ref uint v = ref Unsafe.Add(ref n, k - start);
			Vector128<uint> y0 = Vector128.LoadUnsafe(ref y);
			Vector128<uint> y1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 1));
			Vector128<uint> v0 = Vector128.LoadUnsafe(ref v);
			Vector128<uint> v1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 1));
			nint g = start;

			for (; g < diagonal; g += 4)
			{
				Vector128<uint> ax = Vector128.LoadUnsafe(ref x);
				Vector128<uint> mx = Vector128.LoadUnsafe(ref u);
				Vector128<uint> y2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 2));
				Vector128<uint> v2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 2));
				ab23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23e, y0, ax, 0);
				mn23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23e, v0, mx, 0);
				ab01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01e, y2, ax, 0);
				mn01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01e, v2, mx, 0);
				Vector128<uint> y3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 3));
				Vector128<uint> v3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 3));
				ab23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23f, y1, ax, 1);
				mn23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23f, v1, mx, 1);
				ab01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01f, y3, ax, 1);
				mn01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01f, v3, mx, 1);
				y0 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 4));
				v0 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 4));
				ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, y2, ax, 2);
				mn23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23g, v2, mx, 2);
				ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, y0, ax, 2);
				mn01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01g, v0, mx, 2);
				y1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 5));
				v1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 5));
				ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, y3, ax, 3);
				mn23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23h, v3, mx, 3);
				ab01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01h, y1, ax, 3);
				mn01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01h, v1, mx, 3);
				x = ref Unsafe.Add(ref x, 4);
				u = ref Unsafe.Add(ref u, 4);
				y = ref Unsafe.Subtract(ref y, 4);
				v = ref Unsafe.Subtract(ref v, 4);
			}

			// y points at the word k − diagonal of 2·a. Lane c of the block takes the word c − i, so at i = half, lane k takes a_half and the others 2·a; at i = half + 1, lane k + 2 takes a_(half+1), lane k + 3 the word of 2·a, and lanes k and k + 1 nothing, as their products came at smaller i.
			{
				Vector128<uint> ax = Vector128.LoadUnsafe(ref x);
				Vector128<uint> middle = AdvSimd.BitwiseSelect(thirdLane, Vector128.LoadUnsafe(ref Unsafe.Add(ref a, half - 2)), Vector128.LoadUnsafe(ref Unsafe.Add(ref twice, half - 2)));
				Vector128<uint> next = AdvSimd.BitwiseSelect(thirdLane, Vector128.LoadUnsafe(ref Unsafe.Add(ref a, half - 1)), Vector128.LoadUnsafe(ref Unsafe.Add(ref twice, half - 1)));

				if (diagonal < half)
				{
					Vector128<uint> y2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 2));
					Vector128<uint> y3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref y, 3));
					ab23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23e, y0, ax, 0);
					ab01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01e, y2, ax, 0);
					ab23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23f, y1, ax, 1);
					ab01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01f, y3, ax, 1);
					ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, y2, ax, 2);
					ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, middle, ax, 2);
					ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, next, ax, 3);
				}
				else
				{
					ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, y0, ax, 0);
					ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, middle, ax, 0);
					ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, next, ax, 1);
				}
			}

			// Two groups at a time, the second into the sums of a·a.
			for (; g + 4 < end; g += 8)
			{
				Vector128<uint> mx = Vector128.LoadUnsafe(ref u);
				Vector128<uint> my = Vector128.LoadUnsafe(ref u, 4);
				Vector128<uint> v2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 2));
				Vector128<uint> v3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 3));
				mn23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23e, v0, mx, 0);
				mn01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01e, v2, mx, 0);
				mn23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23f, v1, mx, 1);
				mn01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01f, v3, mx, 1);
				Vector128<uint> v4 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 4));
				Vector128<uint> v5 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 5));
				mn23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23g, v2, mx, 2);
				mn01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01g, v4, mx, 2);
				mn23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23h, v3, mx, 3);
				mn01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01h, v5, mx, 3);
				Vector128<uint> v6 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 6));
				Vector128<uint> v7 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 7));
				ab23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23e, v4, my, 0);
				ab01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01e, v6, my, 0);
				ab23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23f, v5, my, 1);
				ab01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01f, v7, my, 1);
				v0 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 8));
				v1 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 9));
				ab23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23g, v6, my, 2);
				ab01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01g, v0, my, 2);
				ab23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab23h, v7, my, 3);
				ab01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(ab01h, v1, my, 3);
				u = ref Unsafe.Add(ref u, 8);
				v = ref Unsafe.Subtract(ref v, 8);
			}

			if (g < end)
			{
				Vector128<uint> mx = Vector128.LoadUnsafe(ref u);
				Vector128<uint> v2 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 2));
				Vector128<uint> v3 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 3));
				Vector128<uint> v4 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 4));
				Vector128<uint> v5 = Vector128.LoadUnsafe(ref Unsafe.Subtract(ref v, 5));
				mn23e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23e, v0, mx, 0);
				mn01e = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01e, v2, mx, 0);
				mn23f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23f, v1, mx, 1);
				mn01f = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01f, v3, mx, 1);
				mn23g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23g, v2, mx, 2);
				mn01g = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01g, v4, mx, 2);
				mn23h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn23h, v3, mx, 3);
				mn01h = AdvSimd.MultiplyBySelectedScalarWideningUpperAndAdd(mn01h, v5, mx, 3);
			}

			Vector128<ulong> low = ab01e + ab01f + (ab01g + ab01h) + (mn01e + mn01f + (mn01g + mn01h));
			Vector128<ulong> high = ab23e + ab23f + (ab23g + ab23h) + (mn23e + mn23f + (mn23g + mn23h));
			carry = Tail(low, high, carry, ref n, ref m, ref output, k, count, inverse, mask);
		}
	}

	// Columns k to k + 3 from the sums in low and high and the carry into column k in lane 0. A column below count gains its reduction digit times n, which clears its low digit; a column from count on is a digit of the result. Each passes the rest to the next, and the carry out of the block comes back in lane 0; lane 1 here holds what is left over and is ignored.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Tail(Vector128<ulong> low, Vector128<ulong> high, Vector128<ulong> carry, ref uint n, ref uint m, ref ulong output, nint k, nint count, Vector128<uint> inverse, ulong digitMask)
	{
		Vector128<ulong> s0 = low + carry;
		Vector128<ulong> s1 = AdvSimd.Arm64.DuplicateSelectedScalarToVector128(low, 1);
		Vector128<ulong> s2 = high;
		Vector128<ulong> s3 = AdvSimd.Arm64.DuplicateSelectedScalarToVector128(high, 1);

		if (k + 4 <= count)
		{
			Vector128<uint> mask = Vector128.Create((uint)digitMask);
			Vector64<uint> n0 = Vector64.LoadUnsafe(ref n);
			Vector64<uint> n1 = Vector64.LoadUnsafe(ref n, 1);
			Vector64<uint> n2 = Vector64.LoadUnsafe(ref n, 2);
			Vector64<uint> n3 = Vector64.LoadUnsafe(ref n, 3);
			Vector128<uint> q0 = AdvSimd.Multiply(s0.AsUInt32(), inverse) & mask;
			s0 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s0, n0, q0, 0);
			s1 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s1, n1, q0, 0);
			s2 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s2, n2, q0, 0);
			s3 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s3, n3, q0, 0);
			s1 = ShiftRightAdd(s1, s0);
			Vector128<uint> q1 = AdvSimd.Multiply(s1.AsUInt32(), inverse) & mask;
			s1 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s1, n0, q1, 0);
			s2 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s2, n1, q1, 0);
			s3 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s3, n2, q1, 0);
			s2 = ShiftRightAdd(s2, s1);
			Vector128<uint> q2 = AdvSimd.Multiply(s2.AsUInt32(), inverse) & mask;
			s2 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s2, n0, q2, 0);
			s3 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s3, n1, q2, 0);
			s3 = ShiftRightAdd(s3, s2);
			Vector128<uint> q3 = AdvSimd.Multiply(s3.AsUInt32(), inverse) & mask;
			s3 = AdvSimd.MultiplyBySelectedScalarWideningLowerAndAdd(s3, n0, q3, 0);
			Vector128<uint> digits = AdvSimd.Arm64.ZipLow(AdvSimd.Arm64.ZipLow(q0, q1).AsUInt64(), AdvSimd.Arm64.ZipLow(q2, q3).AsUInt64()).AsUInt32();
			digits.StoreUnsafe(ref m, (nuint)k);
			return ShiftRight(s3);
		}

		if (k >= count)
		{
			s1 = ShiftRightAdd(s1, s0);
			s2 = ShiftRightAdd(s2, s1);
			s3 = ShiftRightAdd(s3, s2);
			Vector128<ulong> mask = Vector128.Create(digitMask);
			Vector128<ulong> digits01 = AdvSimd.Arm64.ZipLow(s0, s1) & mask;
			Vector128<ulong> digits23 = AdvSimd.Arm64.ZipLow(s2, s3) & mask;
			ref ulong destination = ref Unsafe.Add(ref output, k - count);

			if (k + 4 <= 2 * count)
			{
				digits01.StoreUnsafe(ref destination);
				digits23.StoreUnsafe(ref destination, 2);
			}
			else
			{
				// The last block, of 1, 2 or 3 columns.
				destination = digits01.ToScalar();

				if (k + 2 <= 2 * count)
				{
					Unsafe.Add(ref destination, 1) = digits01.GetElement(1);
				}

				if (k + 3 <= 2 * count)
				{
					Unsafe.Add(ref destination, 2) = digits23.ToScalar();
				}
			}

			return ShiftRight(s3);
		}

		return Straddle(s0.ToScalar(), s1.ToScalar(), s2.ToScalar(), s3.ToScalar(), ref n, ref m, ref output, k, count, inverse.ToScalar());
	}

	// usra and ushr by the digit size, a constant of each instantiation.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<ulong> ShiftRightAdd(Vector128<ulong> addend, Vector128<ulong> value)
	{
#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return AdvSimd.ShiftRightLogicalAdd(addend, value, (byte)TRadix.Bits);
#pragma warning restore CA1857
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<ulong> ShiftRight(Vector128<ulong> value)
	{
#pragma warning disable CA1857
		// ReSharper disable once ConstantExpected
		return AdvSimd.ShiftRightLogical(value, (byte)TRadix.Bits);
#pragma warning restore CA1857
	}

	// The block across count, column by column; with a single digit, its last two columns are past the result.
	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
	private static Vector128<ulong> Straddle(ulong s0, ulong s1, ulong s2, ulong s3, ref uint n, ref uint m, ref ulong output, nint k, nint count, uint negativeInverse)
	{
		ulong mask = (1UL << TRadix.Bits) - 1;
		Span<ulong> sums = [s0, s1, s2, s3];
		ulong carry = 0;

		for (int j = 0; j < 4; ++j)
		{
			nint c = k + j;
			ulong sum = sums[j] + carry;

			if (c < count)
			{
				uint digit = (uint)sum * negativeInverse & (uint)mask;
				Unsafe.Add(ref m, c) = digit;
				sum += (ulong)digit * n;

				for (int t = j + 1; t < 4; ++t)
				{
					sums[t] += (ulong)digit * Unsafe.Add(ref n, t - j);
				}
			}
			else if (c < 2 * count)
			{
				Unsafe.Add(ref output, c - count) = sum & mask;
			}

			carry = sum >> TRadix.Bits;
		}

		// Erased, as the scratch is.
		sums.ZeroMemory();
		return Vector128.CreateScalar(carry);
	}
}
