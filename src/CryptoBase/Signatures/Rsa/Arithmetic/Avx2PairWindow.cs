namespace CryptoBase.Signatures.Rsa.Arithmetic;

// The vectors of MontgomeryPairKernelAvx2 that stay in registers, as IAvx2Window describes them for MontgomeryKernelAvx2, with the digits of two moduli in alternate lanes: a digit is two lanes wide, so that the shift moves the halves of the vectors.
internal struct Avx2PairWindow : IAvx2Window<Avx2PairWindow>
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
