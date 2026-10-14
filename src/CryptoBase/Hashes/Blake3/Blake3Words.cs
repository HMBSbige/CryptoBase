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
		InlineArray8<uint> words = Unsafe.ReadUnaligned<InlineArray8<uint>>(in source);

		if (!BitConverter.IsLittleEndian)
		{
			BinaryPrimitives.ReverseEndianness(words, words);
		}

		return words;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Store(ref byte destination, ref readonly InlineArray8<uint> words)
	{
		if (BitConverter.IsLittleEndian)
		{
			Unsafe.WriteUnaligned(ref destination, words);
			return;
		}

		for (int i = 0; i < 8; ++i)
		{
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, i * sizeof(uint)), BinaryPrimitives.ReverseEndianness(words[i]));
		}
	}
}
