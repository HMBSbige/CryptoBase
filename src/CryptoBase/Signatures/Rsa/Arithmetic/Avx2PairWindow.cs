namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of MontgomeryPairKernelAvx2 that stay in registers, as IAvx2Window describes them for MontgomeryKernelAvx2, with the digits of two moduli in alternate lanes: a digit is two lanes wide, so that the shift moves the halves of the vectors.
internal interface IAvx2PairWindow<TSelf> where TSelf : struct, IAvx2PairWindow<TSelf>
{
	static abstract int Count { get; }

	static abstract Vector256<ulong> Step(ref TSelf acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low);

	static abstract void Store(ref readonly TSelf acc, ref ulong lanes, Vector256<ulong> offset);
}

internal struct Avx2PairWindow : IAvx2PairWindow<Avx2PairWindow>
{
	private Vector256<ulong> _lanes;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Step(ref Avx2PairWindow acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low)
	{
		Vector256<ulong> sums = Avx2Window.Accumulate(ref blocks, index, acc._lanes, b, m, high, low, out Vector256<ulong> highParts);
		acc._lanes = Shift(sums, above, highParts);
		return sums;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx2PairWindow acc, ref ulong lanes, Vector256<ulong> offset)
	{
		(acc._lanes - offset).StoreUnsafe(ref lanes);
	}

	// The upper half of sums and the lower half of above, plus highParts.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<ulong> Shift(Vector256<ulong> sums, Vector256<ulong> above, Vector256<ulong> highParts)
	{
		return Avx2.Permute2x128(sums, above, 0x21) + highParts;
	}
}

internal struct Avx2PairWindowPair<TLow, THigh> : IAvx2PairWindow<Avx2PairWindowPair<TLow, THigh>> where TLow : struct, IAvx2PairWindow<TLow> where THigh : struct, IAvx2PairWindow<THigh>
{
	private TLow _low;
	private THigh _high;

	public static int Count
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => TLow.Count + THigh.Count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<ulong> Step(ref Avx2PairWindowPair<TLow, THigh> acc, ref ulong blocks, nint index, Vector256<ulong> above, Vector256<double> b, Vector256<double> m, Vector256<double> high, Vector256<double> low)
	{
		return TLow.Step(ref acc._low, ref blocks, index, THigh.Step(ref acc._high, ref blocks, index + Avx2Window.BlockWords * TLow.Count, above, b, m, high, low), b, m, high, low);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Store(ref readonly Avx2PairWindowPair<TLow, THigh> acc, ref ulong lanes, Vector256<ulong> offset)
	{
		TLow.Store(in acc._low, ref lanes, offset);
		THigh.Store(in acc._high, ref Unsafe.Add(ref lanes, 4 * TLow.Count), offset);
	}
}
