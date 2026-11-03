namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of the accumulator of MontgomeryKernelAvx2 that stay in registers, from vector 1 up, as fields that the JIT keeps in registers: Avx2Window is one vector of four lanes, and Avx2WindowPair joins two windows. Their operands lie in staging, a block per vector (see MontgomeryKernelAvx2).
internal interface IAvx2Window<TSelf> where TSelf : struct, IAvx2Window<TSelf>
{
	static abstract int Count { get; }

	// Every vector from the top down, with the block of the lowest one at index of blocks: its lanes gain lo(a·b) + lo(n·m), shift down by one lane, taking lane 0 of above, the lanes of the vector above after the low parts, and gain hi(a·b) + hi(n·m). Returns the lanes of the lowest vector after the low parts.
	static abstract Vector256<ulong> Step(ref TSelf acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low);

	// Stores the lanes less offset, those of the lowest vector at lanes.
	static abstract void Store(ref readonly TSelf acc, ref ulong lanes, Vector256<ulong> offset);
}

internal struct Avx2Window : IAvx2Window<Avx2Window>
{
	// A block of staging: the digits of the left operand and of the modulus as doubles, then the lanes of a vector of the accumulator that is not in a window.
	internal const int BlockWords = 12;

	private Vector256<ulong> _lanes;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Step(ref Avx2Window acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low)
	{
		Vector256<ulong> sums = Accumulate(ref blocks, index, acc._lanes, b, m, high, low, out Vector256<ulong> highParts);
		acc._lanes = Shift(sums, above, highParts);
		return sums;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx2Window acc, ref ulong lanes, Vector256<ulong> offset)
	{
		(acc._lanes - offset).StoreUnsafe(ref lanes);
	}

	// lanes + lo(a·b) + lo(n·m), with a and n from the block at index of blocks, and highParts = hi(a·b) + hi(n·m); see MontgomeryKernelAvx2.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<ulong> Accumulate(ref ulong blocks, nint index, Vector256<ulong> lanes, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low, out Vector256<ulong> highParts)
	{
		Vector256<double> a = Vector256.LoadUnsafe(ref Unsafe.Add(ref blocks, index)).AsDouble();
		Vector256<double> n = Vector256.LoadUnsafe(ref Unsafe.Add(ref blocks, index + 4)).AsDouble();
		Vector256<double> t1 = Fma.MultiplyAdd(a, b, high);
		Vector256<double> t2 = Fma.MultiplyAdd(n, m, high);
		Vector256<double> l1 = Fma.MultiplyAdd(a, b, low - t1);
		Vector256<double> l2 = Fma.MultiplyAdd(n, m, low - t2);
		highParts = t1.AsUInt64() + t2.AsUInt64();
		return l1.AsUInt64() + l2.AsUInt64() + lanes;
	}

	// sums shifted down by one lane, lane 0 of above on top, plus highParts: the upper half of sums and the lower half of above, aligned by a lane within each half.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<ulong> Shift(Vector256<ulong> sums, Vector256<ulong> above, Vector256<ulong> highParts)
	{
		return Avx2.AlignRight(Avx2.Permute2x128(sums, above, 0x21).AsByte(), sums.AsByte(), 8).AsUInt64() + highParts;
	}

	// 2^52 + digit as the bits of a double, less 2^52, for digits below 2^52.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<double> ToDouble(Vector256<ulong> digits)
	{
		Vector256<ulong> bits = Vector256.Create(0x4330000000000000UL);
		return (digits | bits).AsDouble() - bits.AsDouble();
	}
}

internal struct Avx2WindowPair<TLow, THigh> : IAvx2Window<Avx2WindowPair<TLow, THigh>> where TLow : struct, IAvx2Window<TLow> where THigh : struct, IAvx2Window<THigh>
{
	private TLow _low;
	private THigh _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TLow.Count + THigh.Count;
	}

	// The high window first, whose lowest vector the low window takes from above.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Step(ref Avx2WindowPair<TLow, THigh> acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low)
	{
		return TLow.Step(ref acc._low, ref blocks, index, THigh.Step(ref acc._high, ref blocks, index + Avx2Window.BlockWords * TLow.Count, above, b, m, high, low), b, m, high, low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx2WindowPair<TLow, THigh> acc, ref ulong lanes, Vector256<ulong> offset)
	{
		TLow.Store(in acc._low, ref lanes, offset);
		THigh.Store(in acc._high, ref Unsafe.Add(ref lanes, 4 * TLow.Count), offset);
	}
}
