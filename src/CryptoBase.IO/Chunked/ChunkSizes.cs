namespace CryptoBase.IO.Chunked;

/// <summary>
/// Holds the sizes of a chunked cipher for the instances that use them on each operation.
/// </summary>
/// <remarks>The code over <see cref="IChunkedCipher{TSelf}" /> is shared between ciphers, so each use of a static member of the cipher costs a runtime lookup and an indirect call.</remarks>
internal readonly struct ChunkSizes(int headerSize, int chunkSize, int tagSize, long maxChunkCount)
{
	public int HeaderSize { get; } = headerSize;

	public int ChunkSize { get; } = chunkSize;

	public int TagSize { get; } = tagSize;

	public long MaxChunkCount { get; } = maxChunkCount;

	public int EncryptedChunkSize => ChunkSize + TagSize;

	/// <summary>
	/// Gets the length of the largest message: every chunk full but the last, which is one byte short.
	/// </summary>
	public long MaxMessageLength => MaxChunkCount * ChunkSize - 1;

	public long GetChunkOffset(long index)
	{
		return HeaderSize + index * EncryptedChunkSize;
	}
}
