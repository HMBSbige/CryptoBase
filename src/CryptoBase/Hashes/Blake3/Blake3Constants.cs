namespace CryptoBase.Hashes.Blake3;

internal static class Blake3Constants
{
	internal const int KeyLength = 32;
	internal const int OutLength = 32;
	internal const int BlockLengthLog2 = 6;
	internal const int BlockLength = 1 << BlockLengthLog2;
	internal const int ChunkLength = 1024;
	internal const int ChunkBlocks = ChunkLength / BlockLength;
	internal const int Rounds = 7;

	// Input shorter than 2^64 bytes has fewer than 2^54 chunks.
	internal const int MaxDepth = 54;

	// Without prefetching, a single thread hashing input that has outgrown the caches waits on memory.
	internal const int PrefetchDistance = 2 * BlockLength;

	internal const uint IV0 = 0x6A09E667;
	internal const uint IV1 = 0xBB67AE85;
	internal const uint IV2 = 0x3C6EF372;
	internal const uint IV3 = 0xA54FF53A;
	internal const uint IV4 = 0x510E527F;
	internal const uint IV5 = 0x9B05688C;
	internal const uint IV6 = 0x1F83D9AB;
	internal const uint IV7 = 0x5BE0CD19;

	internal static ref readonly InlineArray8<uint> IV => ref Unsafe.As<uint, InlineArray8<uint>>(ref MemoryMarshal.GetReference(IVWords));

	private static ReadOnlySpan<uint> IVWords => [IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7];

	internal static ReadOnlySpan<byte> MessageSchedule =>
	[
		0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15,
		2, 3, 7, 4, 6, 10, 0, 13, 1, 12, 9, 15, 11, 5, 14, 8,
		3, 10, 13, 7, 4, 12, 2, 14, 6, 9, 11, 8, 5, 0, 15, 1,
		10, 12, 14, 13, 7, 9, 3, 15, 4, 11, 5, 1, 0, 2, 8, 6,
		12, 9, 15, 14, 13, 11, 10, 8, 7, 5, 0, 6, 2, 3, 1, 4,
		9, 11, 8, 15, 14, 5, 12, 1, 13, 0, 2, 4, 3, 10, 6, 7,
		11, 5, 1, 8, 15, 0, 9, 6, 14, 2, 3, 7, 10, 12, 4, 13
	];
}
