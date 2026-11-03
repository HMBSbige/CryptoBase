namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The windows of MontgomeryKernelAvx512Staged, as IAvx512Window describes them, with only the accumulator in registers: the digits of the operands lie in staging, a vector of the left operand and then one of the modulus for each vector of the window, from vector 0 on.
// The operations are written out rather than shared with Avx512Window: the largest windows inline so many of them that one more call per operation would exceed what the JIT inlines, and the accumulator would leave the registers. Store writes through a pointer, as that of Avx512Window does.
internal interface IAvx512StagedWindow<TSelf> where TSelf : struct, IAvx512StagedWindow<TSelf>
{
	static abstract int Count { get; }

	// acc += lo(a·b) + lo(n·m), keeping hi(a·b) + hi(n·m) for Shift, with a and n of vector index from staging.
	static abstract void Accumulate(ref TSelf acc, ref double staging, int index, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low);

	static abstract void Shift(ref TSelf acc, Vector512<ulong> next);

	static abstract Vector512<ulong> First(ref readonly TSelf acc);

	static abstract void ReplaceLow(ref TSelf acc, Vector512<ulong> low, Vector512<ulong> mask);

	static abstract Vector512<ulong> Pass(ref TSelf acc, Vector512<ulong> offset, Vector512<ulong> previous);

	static abstract void Masks(ref readonly TSelf acc, int index, Span<ulong> generate, Span<ulong> propagate);

	static abstract void Store(ref readonly TSelf acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length);
}

internal struct Avx512StagedWindow : IAvx512StagedWindow<Avx512StagedWindow>
{
	private const ulong Mask = (1UL << 52) - 1;

	private Vector512<ulong> _lanes;
	private Vector512<ulong> _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Accumulate(ref Avx512StagedWindow acc, ref double staging, int index, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low)
	{
		Vector512<double> a = Vector512.LoadUnsafe(ref staging, (nuint)(16 * index));
		Vector512<double> n = Vector512.LoadUnsafe(ref staging, (nuint)(16 * index + 8));
		Vector512<double> t1 = Avx512F.FusedMultiplyAdd(a, b, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> t2 = Avx512F.FusedMultiplyAdd(n, m, high, FloatRoundingMode.ToNegativeInfinity);
		Vector512<double> l1 = Avx512F.FusedMultiplyAdd(a, b, low - t1);
		Vector512<double> l2 = Avx512F.FusedMultiplyAdd(n, m, low - t2);
		acc._lanes += l1.AsUInt64() + l2.AsUInt64();
		acc._high = t1.AsUInt64() + t2.AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Shift(ref Avx512StagedWindow acc, Vector512<ulong> next)
	{
		acc._lanes = Avx512F.AlignRight64(next, acc._lanes, 1) + acc._high;
	}

	public static Vector512<ulong> First(ref readonly Avx512StagedWindow acc)
	{
		return acc._lanes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ReplaceLow(ref Avx512StagedWindow acc, Vector512<ulong> low, Vector512<ulong> mask)
	{
		acc._lanes = Vector512.ConditionalSelect(mask, low, acc._lanes);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Pass(ref Avx512StagedWindow acc, Vector512<ulong> offset, Vector512<ulong> previous)
	{
		Vector512<ulong> value = acc._lanes - offset;
		Vector512<ulong> carry = value >> 52;
		acc._lanes = (value & Vector512.Create(Mask)) + Avx512F.AlignRight64(carry, previous, 7);
		return carry;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Masks(ref readonly Avx512StagedWindow acc, int index, Span<ulong> generate, Span<ulong> propagate)
	{
		generate[index >> 3] |= Vector512.GreaterThan(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
		propagate[index >> 3] |= Vector512.Equals(acc._lanes, Vector512.Create(Mask)).ExtractMostSignificantBits() << 8 * (index & 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Store(ref readonly Avx512StagedWindow acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length)
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
			Avx512F.MaskStore((ulong*)Unsafe.AsPointer(ref Unsafe.Add(ref result, 8 * index)), Vector512.LessThan(Vector512<ulong>.Indices, Vector512.Create((ulong)remaining)), value);
		}
	}
}

internal struct Avx512StagedWindowPair<TLow, THigh> : IAvx512StagedWindow<Avx512StagedWindowPair<TLow, THigh>> where TLow : struct, IAvx512StagedWindow<TLow> where THigh : struct, IAvx512StagedWindow<THigh>
{
	private TLow _low;
	private THigh _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TLow.Count + THigh.Count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Accumulate(ref Avx512StagedWindowPair<TLow, THigh> acc, ref double staging, int index, Vector512<double> b, Vector512<double> m, Vector512<double> high, Vector512<double> low)
	{
		TLow.Accumulate(ref acc._low, ref staging, index, b, m, high, low);
		THigh.Accumulate(ref acc._high, ref staging, index + TLow.Count, b, m, high, low);
	}

	// The low window takes the first lane of the high one before the high one shifts.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Shift(ref Avx512StagedWindowPair<TLow, THigh> acc, Vector512<ulong> next)
	{
		TLow.Shift(ref acc._low, THigh.First(in acc._high));
		THigh.Shift(ref acc._high, next);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> First(ref readonly Avx512StagedWindowPair<TLow, THigh> acc)
	{
		return TLow.First(in acc._low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void ReplaceLow(ref Avx512StagedWindowPair<TLow, THigh> acc, Vector512<ulong> low, Vector512<ulong> mask)
	{
		TLow.ReplaceLow(ref acc._low, low, mask);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<ulong> Pass(ref Avx512StagedWindowPair<TLow, THigh> acc, Vector512<ulong> offset, Vector512<ulong> previous)
	{
		return THigh.Pass(ref acc._high, offset, TLow.Pass(ref acc._low, offset, previous));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Masks(ref readonly Avx512StagedWindowPair<TLow, THigh> acc, int index, Span<ulong> generate, Span<ulong> propagate)
	{
		TLow.Masks(in acc._low, index, generate, propagate);
		THigh.Masks(in acc._high, index + TLow.Count, generate, propagate);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx512StagedWindowPair<TLow, THigh> acc, int index, ReadOnlySpan<ulong> carries, ref ulong result, int length)
	{
		TLow.Store(in acc._low, index, carries, ref result, length);
		THigh.Store(in acc._high, index + TLow.Count, carries, ref result, length);
	}
}
