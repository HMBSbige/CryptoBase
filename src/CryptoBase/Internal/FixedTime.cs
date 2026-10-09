namespace CryptoBase.Internal;

internal static class FixedTime
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool Equals16(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
	{
		Debug.Assert(left.Length is 16 && right.Length is 16);
		ref byte leftRef = ref MemoryMarshal.GetReference(left);
		ref byte rightRef = ref MemoryMarshal.GetReference(right);
		ulong low = Unsafe.ReadUnaligned<ulong>(ref leftRef) ^ Unsafe.ReadUnaligned<ulong>(ref rightRef);
		ulong high = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref leftRef, sizeof(ulong))) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref rightRef, sizeof(ulong)));
		return (low | high) is 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool Equals16(Vector128<byte> left, Vector128<byte> right)
	{
		Vector128<byte> difference = left ^ right;

		// The software fallback of == returns at the first unequal element.
		if (Vector128.IsHardwareAccelerated)
		{
			return difference == Vector128<byte>.Zero;
		}

		Vector128<ulong> halves = difference.AsUInt64();
		return (halves.GetElement(0) | halves.GetElement(1)) is 0;
	}
}
