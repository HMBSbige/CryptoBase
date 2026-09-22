namespace CryptoBase.Hashes;

internal static class HashCoreUtils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadSixteenBigEndianWords(out uint destination, ref byte source)
	{
		LoadFourBigEndianWords(out destination, ref source);
		LoadFourBigEndianWords(out Unsafe.Add(ref destination, 4), ref Unsafe.Add(ref source, 16));
		LoadFourBigEndianWords(out Unsafe.Add(ref destination, 8), ref Unsafe.Add(ref source, 32));
		LoadFourBigEndianWords(out Unsafe.Add(ref destination, 12), ref Unsafe.Add(ref source, 48));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadFourBigEndianWords(out uint destination, ref byte source)
	{
		destination = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref source));
		Unsafe.Add(ref destination, 1) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 4)));
		Unsafe.Add(ref destination, 2) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 8)));
		Unsafe.Add(ref destination, 3) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, 12)));
	}

	[SkipLocalsInit]
	internal static int FinalizeCopy<TCore>(TCore state, Span<byte> destination) where TCore : unmanaged, IIncrementalHashCore
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		Span<byte> hash = stackalloc byte[TCore.HashLength];
		state.Finalize(hash);
		hash.CopyTo(destination);
		return TCore.HashLength;
	}
}
