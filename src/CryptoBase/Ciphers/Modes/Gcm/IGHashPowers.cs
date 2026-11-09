namespace CryptoBase.Ciphers.Modes.Gcm;

internal interface IGHashPrecomputedKey
{
	void Initialize(Vector128<byte> key);
}

internal interface IGHashPowers : IGHashPrecomputedKey
{
	void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock);
}

internal interface IGHashFoldedPowers : IGHashPowers
{
	static abstract int BatchBlocks { get; }

	void AppendBlocks(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source);

	void AppendFoldedTail(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock, int blockCount);
}
