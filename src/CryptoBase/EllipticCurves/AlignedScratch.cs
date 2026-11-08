namespace CryptoBase.EllipticCurves;

// Scratch for the operands and products of vector rounds on a 64-byte boundary: the stack keeps 16-byte alignment only, so at some offsets of the stack a vector of 32 or 64 bytes in the frame would cross a cache line, and each load and store of it would touch two. A buffer on the stack holds the values and the at most 48 bytes that aligning them skips, and stays where it is.
internal static class AlignedScratch
{
	// The first value of T at the first 64-byte boundary in buffer, a local of the caller.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe ref T Start<TBuffer, T>(ref TBuffer buffer) where TBuffer : unmanaged where T : unmanaged
	{
		ref byte start = ref Unsafe.As<TBuffer, byte>(ref buffer);
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		return ref Unsafe.As<byte, T>(ref Unsafe.AddByteOffset(ref start, (address + 63 & ~(nuint)63) - address));
	}
}

// Five values of SM2Field29x4Avx2, nine vectors each, and two vectors to align them.
[InlineArray(5 * 9 + 2)]
internal struct SM2QuadScratch5
{
	private Vector256<ulong> _element;
}

// Six values of SM2Field29x4Avx2 and two vectors to align them.
[InlineArray(6 * 9 + 2)]
internal struct SM2QuadScratch6
{
	private Vector256<ulong> _element;
}

// Five values of SM2Field29x8Avx512 and a vector to align them.
[InlineArray(5 * 9 + 1)]
internal struct SM2OctoScratch5
{
	private Vector512<ulong> _element;
}
