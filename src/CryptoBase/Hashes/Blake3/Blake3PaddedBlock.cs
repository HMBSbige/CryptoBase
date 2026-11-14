using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Writes the zero-padded last block of a chunk in 16-byte stores, so that every later load of 16 bytes or a word is forwarded from a single store.
internal static class Blake3PaddedBlock
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store(ref byte destination, ref readonly byte source, int length)
	{
		Debug.Assert(length is >= 0 and <= BlockLength);

		if (!Vector128.IsHardwareAccelerated)
		{
			Span<byte> block = MemoryMarshal.CreateSpan(ref destination, BlockLength);
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
	}
}
