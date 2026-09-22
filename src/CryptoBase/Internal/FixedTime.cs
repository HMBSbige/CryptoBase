namespace CryptoBase.Internal;

internal static class FixedTime
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool Equals16(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
	{
		Debug.Assert(left.Length is 16 && right.Length is 16);
		ref byte leftRef = ref left.GetReference();
		ref byte rightRef = ref right.GetReference();
		ulong low = Unsafe.ReadUnaligned<ulong>(ref leftRef) ^ Unsafe.ReadUnaligned<ulong>(ref rightRef);
		ulong high = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref leftRef, sizeof(ulong))) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rightRef, sizeof(ulong)));
		return (low | high) is 0;
	}
}
