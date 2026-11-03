namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of MontgomeryKernelAvx512, as fields that the JIT keeps in registers: Avx512Window is one vector of eight lanes, and Avx512WindowPair joins two windows, so that every size is a type and its operations inline into straight-line code.
// A window holds three things per vector: digits of an operand as doubles, the lanes of the accumulator, and the high parts of the products that a step keeps between Accumulate and Shift. Operand windows use only the first, accumulators only the others.
// Load and Store reach the lanes below length with masked loads and stores, which take pointers: the kernel keeps digits and result pinned.
internal interface IAvx512Window<TSelf> where TSelf : struct, IAvx512Window<TSelf>
{
	static abstract int Count { get; }

	// The digits from vector index on, as doubles, zero past length.
	static abstract void Load(ref TSelf window, ref ulong digits, int length, int index);

	// acc += lo(a·b) + lo(n·m), keeping hi(a·b) + hi(n·m) for Shift; see MontgomeryKernelAvx512.
	static abstract void Accumulate(ref TSelf acc, ref readonly TSelf a, ref readonly TSelf n, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low);

	// acc shifted down by one lane, with lane 0 of next in its top lane, plus the high parts that Accumulate kept.
	static abstract void Shift(ref TSelf acc, Vector512<ulong> next);

	static abstract Vector512<ulong> First(ref readonly TSelf acc);

	// The lanes of the first vector where mask is set replaced by those of low.
	static abstract void ReplaceLow(ref TSelf acc, Vector512<ulong> low, Vector512<ulong> mask);

	// acc −= offset, then the carries of each lane added to the next, which leaves every lane below 2^52 + 2^9. previous holds the carries of the vector before; returns those of the last vector.
	static abstract Vector512<ulong> Pass(ref TSelf acc, Vector512<ulong> offset, Vector512<ulong> previous);

	// Bit j of word index/8, shifted by 8·(index mod 8), set in generate for lane j of vector index at or above 2^52, and in propagate for one equal to 2^52 − 1.
	static abstract void Masks(ref readonly TSelf acc, int index, Span<ulong> generate, Span<ulong> propagate);

	// Adds the carry that reaches each lane, as the bits of carries in the layout of Masks give it, reduces to 52 bits and stores the lanes below length.
	static abstract void Store(ref readonly TSelf acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length);
}

internal struct Avx512Window : IAvx512Window<Avx512Window>
{
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

	// The low window takes the first lane of the high one before the high one shifts.
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
