namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of MontgomeryKernelAvx512, as fields that the JIT keeps in registers: Avx512Window is one vector of eight lanes, and Avx512WindowPair joins two windows, so that every size is a type and its operations inline into straight-line code.
// A window holds three things per vector: digits of an operand as doubles, the lanes of the accumulator, and the high parts of the products that a step keeps between Accumulate and Shift. Operand windows use only the first, accumulators only the others.
// Load and Store reach the lanes below length with masked loads and stores, which take pointers: the kernel keeps digits and result pinned.
internal interface IAvx512Accumulator<TSelf> where TSelf : struct, IAvx512Accumulator<TSelf>
{
	// Bit j of word index/8, shifted by 8·(index mod 8), set in generate for lane j of vector index at or above 2^52, and in propagate for one equal to 2^52 − 1.
	static abstract void Masks(ref readonly TSelf acc, int index, Span<ulong> generate, Span<ulong> propagate);

	// Adds the carry that reaches each lane, as the bits of carries in the layout of Masks give it, reduces to 52 bits and stores the lanes below length.
	static abstract void Store(ref readonly TSelf acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length);
}

internal interface IAvx512Window<TSelf> : IAvx512Accumulator<TSelf> where TSelf : struct, IAvx512Window<TSelf>
{
	static abstract int Count { get; }

	// The digits from vector index on, as doubles, zero past length.
	static abstract void Load(ref TSelf window, ref ulong digits, int length, int index);

	// acc += lo(a·b) + lo(n·m), keeping hi(a·b) + hi(n·m) for Shift; see MontgomeryKernelAvx512.
	static abstract void Accumulate(ref TSelf acc, ref readonly TSelf a, ref readonly TSelf n, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low);

	// acc shifted down by one digit, with the first digit of next on top, plus the high parts that Accumulate kept. A digit is one lane, or two in Avx512PairWindow.
	static abstract void Shift(ref TSelf acc, Vector512<ulong> next);

	static abstract Vector512<ulong> First(ref readonly TSelf acc);

	// The lanes of the first vector where mask is set replaced by those of low.
	static abstract void ReplaceLow(ref TSelf acc, Vector512<ulong> low, Vector512<ulong> mask);

	// acc −= offset, then the carries of each lane added to the next digit of its modulus, which leaves every lane below 2^52 + 2^9. previous holds the carries of the vector before; returns those of the last vector.
	static abstract Vector512<ulong> Pass(ref TSelf acc, Vector512<ulong> offset, Vector512<ulong> previous);
}

internal struct Avx512Window : IAvx512Window<Avx512Window>
{
	// The bits of 2^104 and of 2^52; the lane shifted in at iteration i carries LowOffset + i·Offset, the offset of every lane after the low parts of that iteration.
	internal const ulong HighBits = 0x4670000000000000UL;
	internal const ulong LowBits = 0x4330000000000000UL;
	internal const ulong LowOffset = 2 * LowBits;
	internal const ulong Offset = unchecked(2 * LowBits + 2 * HighBits);

	private const ulong Mask = (1UL << 52) - 1;

	private Vector512<double> _digits;
	private Vector512<ulong> _lanes;
	private Vector512<ulong> _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Load(ref Avx512Window window, ref ulong digits, int length, int index)
	{
		int remaining = length - 8 * index;
		Vector512<ulong> value = remaining >= 8 ? Vector512.LoadUnsafe(ref digits, (nuint)(8 * index)) : Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref digits, 8 * index)), LaneMask(remaining), Vector512<ulong>.Zero);
		window._digits = Avx512DQ.ConvertToVector512Double(value);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Accumulate(ref Avx512Window acc, ref readonly Avx512Window a, ref readonly Avx512Window n, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low)
	{
		Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a._digits, b, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> t2 = Avx512F.FusedMultiplyAdd(n._digits, m, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> l1 = Avx512F.FusedMultiplyAdd(a._digits, b, low - t1);
		Vector512<double> l2 = Avx512F.FusedMultiplyAdd(n._digits, m, low - t2);
		acc._lanes += l1.AsUInt64() + l2.AsUInt64();
		acc._high = t1.AsUInt64() + t2.AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Shift(ref Avx512Window acc, Vector512<ulong> next)
	{
		acc._lanes = Avx512F.AlignRight64(next, acc._lanes, 1) + acc._high;
	}

	public static Vector512<ulong> First(ref readonly Avx512Window acc)
	{
		return acc._lanes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ReplaceLow(ref Avx512Window acc, Vector512<ulong> low, Vector512<ulong> mask)
	{
		acc._lanes = Vector512.ConditionalSelect(mask, low, acc._lanes);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Pass(ref Avx512Window acc, Vector512<ulong> offset, Vector512<ulong> previous)
	{
		Vector512<ulong> value = acc._lanes - offset;
		Vector512<ulong> carry = value >> 52;
		acc._lanes = (value & Vector512.Create(Mask)) + Avx512F.AlignRight64(carry, previous, 7);
		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Masks(ref readonly Avx512Window acc, int index, Span<ulong> generate, Span<ulong> propagate)
	{
		generate[index >> 3] |= Vector512.GreaterThan(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
		propagate[index >> 3] |= Vector512.Equals(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Store(ref readonly Avx512Window acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length)
	{
		ulong bits = carries[index >> 3] >> 8 * (index & 7);
		Vector512<ulong> value = acc._lanes + (Avx512F.ShiftRightLogicalVariable(Vector512.Create(bits), Vector512<ulong>.Indices) & Vector512<ulong>.One) & Vector512.Create(Mask);
		int remaining = length - 8 * index;

		if (remaining >= 8)
		{
			value.StoreUnsafe(ref result, (nuint)(8 * index));
		}
		else if (remaining > 0)
		{
			Avx512F.MaskStore((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref result, 8 * index)), LaneMask(remaining), value);
		}
	}

	// All ones in the lanes below count.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<ulong> LaneMask(int count)
	{
		return Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Max(count, 0)));
	}

	// Row 0: each digit b_i of the right operand as a double. Rows 1 to 5, each of row words: the parts of its products with the first four digits of the left one that lanes 0 to 4 gain at iteration i: lo(a0·b_i), then hi(a_{j−1}·b_i) + lo(a_j·b_i), then hi(a3·b_i). Eight digits at a time.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe void Products(ref ulong x, ref ulong y, int count, ref ulong rows, int row, Vector512<double> high, Vector512<double> low)
	{
		Vector512<double> a0 = Vector512.Create((double)x);
		Vector512<double> a1 = Vector512.Create((double)Digit(ref x, count, 1));
		Vector512<double> a2 = Vector512.Create((double)Digit(ref x, count, 2));
		Vector512<double> a3 = Vector512.Create((double)Digit(ref x, count, 3));
		Vector512<ulong> highBits = Vector512.Create(HighBits);
		Vector512<ulong> lowBits = Vector512.Create(LowBits);

		for (int j = 0; j < count; j += 8)
		{
			Vector512<ulong> lanes = Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)Math.Min(count - j, 8)));
			Vector512<double> b = Avx512DQ.ConvertToVector512Double(Avx512F.MaskLoad((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref y, j)), lanes, Vector512<ulong>.Zero));
			Vector512<double> t0 = Avx512F.FusedMultiplyAdd(a0, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a1, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t2 = Avx512F.FusedMultiplyAdd(a2, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<double> t3 = Avx512F.FusedMultiplyAdd(a3, b, high, FloatRoundingMode.ToNegativeInfinity);
			Vector512<ulong> l0 = Avx512F.FusedMultiplyAdd(a0, b, low - t0).AsUInt64() - lowBits;
			Vector512<ulong> l1 = Avx512F.FusedMultiplyAdd(a1, b, low - t1).AsUInt64() - lowBits;
			Vector512<ulong> l2 = Avx512F.FusedMultiplyAdd(a2, b, low - t2).AsUInt64() - lowBits;
			Vector512<ulong> l3 = Avx512F.FusedMultiplyAdd(a3, b, low - t3).AsUInt64() - lowBits;
			StoreLanes(b.AsUInt64(), ref rows, j, lanes);
			StoreLanes(l0, ref rows, row + j, lanes);
			StoreLanes(t0.AsUInt64() - highBits + l1, ref rows, 2 * row + j, lanes);
			StoreLanes(t1.AsUInt64() - highBits + l2, ref rows, 3 * row + j, lanes);
			StoreLanes(t2.AsUInt64() - highBits + l3, ref rows, 4 * row + j, lanes);
			StoreLanes(t3.AsUInt64() - highBits, ref rows, 5 * row + j, lanes);
		}
	}

	// Digit index of a value of count digits, zero past them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong Digit(ref ulong digits, int count, int index)
	{
		return index < count ? Unsafe.Add(ref digits, index) : 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe void StoreLanes(Vector512<ulong> value, ref ulong output, int index, Vector512<ulong> lanes)
	{
		Avx512F.MaskStore((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref output, index)), lanes, value);
	}

	// The ripple of carries, a word of 64 lanes at a time, then the stores.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Normalize<TWindow>(ref TWindow acc, ref ulong result, int count) where TWindow : struct, IAvx512Accumulator<TWindow>
	{
		int words = (count + 63) / 64;
		MaskWords generateWords = default;
		MaskWords propagateWords = default;
		Span<ulong> generate = generateWords;
		Span<ulong> propagate = propagateWords;
		TWindow.Masks(in acc, 0, generate, propagate);
		ulong carry = 0;

		for (int w = 0; w < words; ++w)
		{
			ulong shifted = generate[w] << 1 | carry;
			ulong sum = shifted + propagate[w];
			carry = generate[w] >> 63 | (shifted & propagate[w] | (shifted | propagate[w]) & ~sum) >> 63;
			generate[w] = sum ^ propagate[w];
		}

		TWindow.Store(in acc, 0, generate, ref result, count);
		// Erased, as the scratch is.
		generate.ZeroMemory();
		propagate.ZeroMemory();
	}

	[InlineArray(3)]
	internal struct MaskWords
	{
		public const int Length = 3;

		private ulong _element;
	}
}

internal struct Avx512WindowPair<TLow, THigh> : IAvx512Window<Avx512WindowPair<TLow, THigh>> where TLow : struct, IAvx512Window<TLow> where THigh : struct, IAvx512Window<THigh>
{
	private TLow _low;
	private THigh _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TLow.Count + THigh.Count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Load(ref Avx512WindowPair<TLow, THigh> window, ref ulong digits, int length, int index)
	{
		TLow.Load(ref window._low, ref digits, length, index);
		THigh.Load(ref window._high, ref digits, length, index + TLow.Count);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Accumulate(ref Avx512WindowPair<TLow, THigh> acc, ref readonly Avx512WindowPair<TLow, THigh> a, ref readonly Avx512WindowPair<TLow, THigh> n, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low)
	{
		TLow.Accumulate(ref acc._low, in a._low, in n._low, b, m, high, low);
		THigh.Accumulate(ref acc._high, in a._high, in n._high, b, m, high, low);
	}

	// The low window takes the first digit of the high one before the high one shifts.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Shift(ref Avx512WindowPair<TLow, THigh> acc, Vector512<ulong> next)
	{
		TLow.Shift(ref acc._low, THigh.First(in acc._high));
		THigh.Shift(ref acc._high, next);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> First(ref readonly Avx512WindowPair<TLow, THigh> acc)
	{
		return TLow.First(in acc._low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ReplaceLow(ref Avx512WindowPair<TLow, THigh> acc, Vector512<ulong> low, Vector512<ulong> mask)
	{
		TLow.ReplaceLow(ref acc._low, low, mask);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Pass(ref Avx512WindowPair<TLow, THigh> acc, Vector512<ulong> offset, Vector512<ulong> previous)
	{
		return THigh.Pass(ref acc._high, offset, TLow.Pass(ref acc._low, offset, previous));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Masks(ref readonly Avx512WindowPair<TLow, THigh> acc, int index, Span<ulong> generate, Span<ulong> propagate)
	{
		TLow.Masks(in acc._low, index, generate, propagate);
		THigh.Masks(in acc._high, index + TLow.Count, generate, propagate);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx512WindowPair<TLow, THigh> acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length)
	{
		TLow.Store(in acc._low, index, carries, ref result, length);
		THigh.Store(in acc._high, index + TLow.Count, carries, ref result, length);
	}
}
