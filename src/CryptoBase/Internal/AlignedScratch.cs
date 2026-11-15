namespace CryptoBase.Internal;

// Scratch for vector rounds on a 64-byte boundary, or with Start on any power of two.
// The stack keeps only 16-byte alignment, so a wider vector could cross a cache line.
// The buffer holds the values and the bytes skipped to align them, fewer than the alignment.
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

	// The first limb of a pinned array on a 64-byte boundary.
	// Array data is aligned to its 8-byte elements, so the boundary falls on a whole limb.
	internal static int AlignedStart(ulong[] storage)
	{
		nint address = Marshal.UnsafeAddrOfPinnedArrayElement(storage, 0);
		return (int)(-address & Alignment - 1) / sizeof(ulong);
	}

	// The first value of T at the first address in buffer that is a multiple of alignment, a power of two.
	// If buffer moves meanwhile, only the speed changes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe ref T Start<TBuffer, T>(ref TBuffer buffer, nuint alignment = Alignment) where TBuffer : unmanaged where T : unmanaged
	{
		ref byte start = ref Unsafe.As<TBuffer, byte>(ref buffer);
		nuint address = (nuint)Unsafe.AsPointer(ref start);
		return ref Unsafe.As<byte, T>(ref Unsafe.AddByteOffset(ref start, (address + (alignment - 1) & ~(alignment - 1)) - address));
	}
}
