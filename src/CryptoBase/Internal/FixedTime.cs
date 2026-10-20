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

	// Must not exit early: the time may depend on the length but not on the contents.
	internal static bool Equals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
	{
		Debug.Assert(left.Length == right.Length);

		ref byte x = ref MemoryMarshal.GetReference(left);
		ref byte y = ref MemoryMarshal.GetReference(right);
		nuint length = (nuint)left.Length;

		if (Vector512.IsHardwareAccelerated && length >= (nuint)Vector512<byte>.Count)
		{
			nuint last = length - (nuint)Vector512<byte>.Count;
			Vector512<byte> difference = Vector512.LoadUnsafe(ref x, last) ^ Vector512.LoadUnsafe(ref y, last);

			for (nuint i = 0; i < last; i += (nuint)Vector512<byte>.Count)
			{
				difference |= Vector512.LoadUnsafe(ref x, i) ^ Vector512.LoadUnsafe(ref y, i);
			}

			return difference == Vector512<byte>.Zero;
		}

		if (Vector256.IsHardwareAccelerated && length >= (nuint)Vector256<byte>.Count)
		{
			nuint last = length - (nuint)Vector256<byte>.Count;
			Vector256<byte> difference = Vector256.LoadUnsafe(ref x, last) ^ Vector256.LoadUnsafe(ref y, last);

			for (nuint i = 0; i < last; i += (nuint)Vector256<byte>.Count)
			{
				difference |= Vector256.LoadUnsafe(ref x, i) ^ Vector256.LoadUnsafe(ref y, i);
			}

			return difference == Vector256<byte>.Zero;
		}

		if (Vector128.IsHardwareAccelerated && length >= (nuint)Vector128<byte>.Count)
		{
			nuint last = length - (nuint)Vector128<byte>.Count;
			Vector128<byte> difference = Vector128.LoadUnsafe(ref x, last) ^ Vector128.LoadUnsafe(ref y, last);

			for (nuint i = 0; i < last; i += (nuint)Vector128<byte>.Count)
			{
				difference |= Vector128.LoadUnsafe(ref x, i) ^ Vector128.LoadUnsafe(ref y, i);
			}

			return difference == Vector128<byte>.Zero;
		}

		ulong accumulated = 0;
		nuint offset = 0;

		for (; length - offset >= sizeof(ulong); offset += sizeof(ulong))
		{
			accumulated |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref x, offset)) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref y, offset));
		}

		for (; offset < length; ++offset)
		{
			accumulated |= (uint)(Unsafe.Add(ref x, offset) ^ Unsafe.Add(ref y, offset));
		}

		return accumulated is 0;
	}
}
