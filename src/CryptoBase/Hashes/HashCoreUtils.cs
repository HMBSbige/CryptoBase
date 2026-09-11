namespace CryptoBase.Hashes;

internal static class HashCoreUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadFourBigEndianWords(out uint destination, ref byte source)
	{
		destination = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref source));
		Unsafe.Add(ref destination, 1) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 4)));
		Unsafe.Add(ref destination, 2) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 8)));
		Unsafe.Add(ref destination, 3) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 12)));
	}

	[SkipLocalsInit]
	internal static int FinalizeCopy<TCore>(TCore state, Span<byte> destination) where TCore : unmanaged, IIncrementalHashCore
	{
		try
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLengthInBytes, nameof(destination));

			using CryptoBuffer<byte> hash = new(stackalloc byte[TCore.HashLengthInBytes]);
			state.Finalize(hash.Span);
			hash.Span.CopyTo(destination);
			return TCore.HashLengthInBytes;
		}
		finally
		{
			state.ZeroMemory();
		}
	}
}
