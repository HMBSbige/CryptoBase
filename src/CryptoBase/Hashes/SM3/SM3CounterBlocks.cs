namespace CryptoBase.Hashes.SM3;

// What the blocks SM3(prefix ‖ ct) share for the 32-bit big-endian counters ct of the KDF: the chaining value after the whole blocks of the prefix, and the last one or two blocks, the rest of the prefix, ct, the padding and the length, with the bytes of ct zero, which alone differ from one counter to the next. It holds words of the prefix, so erase it once done.
internal struct SM3CounterBlocks
{
	internal InlineArray8<uint> ChainingValue;

	// Both blocks as big-endian words; the second only if TwoBlocks.
	internal InlineArray32<uint> Words;

	// The byte of the blocks where ct starts, the length of the prefix mod 64: ct may run on into the second block for 61 to 63.
	internal int Offset;

	// The padding takes 9 bytes after ct, so a second block for an offset above 51.
	internal readonly bool TwoBlocks => Offset > 51;
}
