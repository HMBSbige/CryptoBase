namespace CryptoBase.Hashes.Sha3;

// A single state, whose interleaved layout is the ordinary one, so every platform has a kernel.
internal readonly struct KeccakP1600Times1 : IKeccakP1600Kernel
{
	public static bool IsSupported => true;

	public static int Lanes => 1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Permute(ref ulong state)
	{
		KeccakP1600.Permute(ref Unsafe.As<ulong, InlineArray25<ulong>>(ref state));
	}
}
