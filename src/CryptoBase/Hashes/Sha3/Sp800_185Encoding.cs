namespace CryptoBase.Hashes.Sha3;

// The integer encodings of SP 800-185, Sec. 2.3.1, each packed into a word: its bytes in order from the least significant byte, as a little-endian store writes them, with zeros past its length. The values encoded are rates and lengths in bits of spans, all below 2^56, so every encoding fits.
internal static class Sp800_185Encoding
{
	// The length of either encoding of value.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int EncodedLength(ulong value)
	{
		return ByteCount(value) + 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong LeftEncode(ulong value)
	{
		int count = ByteCount(value);
		return BigEndianBytes(value, count) << 8 | (uint)count;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static ulong RightEncode(ulong value)
	{
		int count = ByteCount(value);
		return BigEndianBytes(value, count) | (ulong)count << count * 8;
	}

	// Setting the lowest bit gives 0 the one byte that it takes, and leaves the count of every other value unchanged.
	private static int ByteCount(ulong value)
	{
		Debug.Assert(value < 1UL << 56);

		return sizeof(ulong) * 8 + 7 - BitOperations.LeadingZeroCount(value | 1) >> 3;
	}

	// The count low-order bytes of value, most significant first.
	private static ulong BigEndianBytes(ulong value, int count)
	{
		return BinaryPrimitives.ReverseEndianness(value) >> (sizeof(ulong) - count) * 8;
	}
}
