namespace CryptoBase.Hashes.Blake3;

internal static class Blake3Words
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static InlineArray8<uint> Copy(ref readonly uint words)
	{
		return Unsafe.As<uint, InlineArray8<uint>>(ref Unsafe.AsRef(in words));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static InlineArray8<uint> Load(ref readonly byte source)
	{
		return Unsafe.ReadUnaligned<InlineArray8<uint>>(in source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store(ref byte destination, ref readonly InlineArray8<uint> words)
	{
		Unsafe.WriteUnaligned(ref destination, words);
	}
}
