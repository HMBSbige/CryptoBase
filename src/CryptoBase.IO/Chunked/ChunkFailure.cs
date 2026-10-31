namespace CryptoBase.IO.Chunked;

/// <summary>
/// The ways the decryption of a chunked message fails after its header matched.
/// </summary>
internal enum ChunkFailure
{
	None,

	/// <summary>The length is invalid, or the storage ended early.</summary>
	Truncated,

	/// <summary>A chunk failed authentication.</summary>
	ChunkMismatch,

	/// <summary>The message would have more chunks than the cipher allows.</summary>
	TooManyChunks
}
