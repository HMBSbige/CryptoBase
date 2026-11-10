namespace CryptoBase.EllipticCurves;

// Scratch for the operands and products of vector rounds on a 64-byte boundary: the stack keeps 16-byte alignment only, so at some offsets of the stack a vector of 32 or 64 bytes in the frame would cross a cache line, and each load and store of it would touch two. A buffer on the stack holds the values and the bytes that aligning them skips, at most 48 in a buffer of vectors and 63 in one of bytes, and stays where it is.
internal static class AlignedScratch
{
	private const int Alignment = 64;

	// The bytes of storage for count values of T, with room to start them on a 64-byte line.
	internal static int StorageLength<T>(int count) where T : unmanaged
	{
		return count * Unsafe.SizeOf<T>() + Alignment - 1;
	}

	// count values in storage of StorageLength<T>(count) bytes, from its first 64-byte line, where the writes of a vector do not straddle a line and so forward to the reads of the next product.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Span<T> Align<T>(Span<byte> storage, int count) where T : unmanaged
	{
		return MemoryMarshal.Cast<byte, T>(storage.Slice(Offset(storage), count * Unsafe.SizeOf<T>()));
	}

	// A value in storage of StorageLength<T>(1) bytes, from its first 64-byte line, so that the vector stores of a lookup into it forward to the reads that follow them.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ref T AlignEntry<T>(Span<byte> storage) where T : unmanaged
	{
		return ref MemoryMarshal.AsRef<T>(storage.Slice(Offset(storage), Unsafe.SizeOf<T>()));
	}

	// The offset of the first 64-byte line in storage.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe int Offset(Span<byte> storage)
	{
		nint address = (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(storage));
		return (int)(-address & Alignment - 1);
	}

	// A pinned array with room for length limbs from AlignedStart on.
	internal static ulong[] AllocatePinned(int length)
	{
		return GC.AllocateUninitializedArray<ulong>(length + Alignment / sizeof(ulong) - 1, true);
	}

	// The first limb of a pinned array on a 64-byte boundary. Array data is aligned to its 8-byte elements, so the boundary falls on a whole limb.
	internal static int AlignedStart(ulong[] storage)
	{
		nint address = Marshal.UnsafeAddrOfPinnedArrayElement(storage, 0);
		return (int)(-address & Alignment - 1) / sizeof(ulong);
	}

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
