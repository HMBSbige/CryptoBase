using static CryptoBase.Hashes.Blake2.Blake2bState;

namespace CryptoBase.Hashes.Blake2;

// Writes the zero-padded final block of a one-shot hash in 16-byte stores, so that every later load of a message pair or word is forwarded from a single store.
internal static class Blake2bPaddedBlock
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store(ref byte destination, ref readonly byte source, int length)
	{
		Debug.Assert(length is >= 0 and < BlockSizeInBytes);

		if (!Vector128.IsHardwareAccelerated)
		{
			Span<byte> block = MemoryMarshal.CreateSpan(ref destination, BlockSizeInBytes);
			MemoryMarshal.CreateReadOnlySpan(in source, length).CopyTo(block);
			block.Slice(length).Clear();
			return;
		}

		// Branching on the length, which is public, lets whole and zero pieces skip the shuffle.
		ref byte input = ref Unsafe.AsRef(in source);
		Vector128.LoadZeroPaddedUnsafe(ref input, 0, length).StoreUnsafe(ref destination);
		Vector128.LoadZeroPaddedUnsafe(ref input, 16, length).StoreUnsafe(ref destination, 16);
		Vector128.LoadZeroPaddedUnsafe(ref input, 32, length).StoreUnsafe(ref destination, 32);
		Vector128.LoadZeroPaddedUnsafe(ref input, 48, length).StoreUnsafe(ref destination, 48);
		Vector128.LoadZeroPaddedUnsafe(ref input, 64, length).StoreUnsafe(ref destination, 64);
		Vector128.LoadZeroPaddedUnsafe(ref input, 80, length).StoreUnsafe(ref destination, 80);
		Vector128.LoadZeroPaddedUnsafe(ref input, 96, length).StoreUnsafe(ref destination, 96);
		Vector128.LoadZeroPaddedUnsafe(ref input, 112, length).StoreUnsafe(ref destination, 112);
	}
}
