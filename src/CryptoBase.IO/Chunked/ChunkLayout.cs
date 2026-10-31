using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.IO.Chunked;

/// <summary>
/// Maps a chunked message onto its encrypted form and reports the ways its decryption fails.
/// </summary>
/// <remarks>
/// The encrypted form is the header followed by the encrypted chunks. Every chunk but the last is full, and the last holds less than a full chunk, so a valid length never ends on a chunk boundary.
/// </remarks>
internal static class ChunkLayout<TCipher> where TCipher : class, IChunkedCipher<TCipher>
{
	// Every offset of the largest message must fit in a long, and a header plus an encrypted chunk in one array.
	private static bool IsSupported => TCipher.HeaderSize >= 0
		&& TCipher.ChunkSize > 0
		&& TCipher.TagSize > 0
		&& TCipher.ChunkSize <= (long)Array.MaxLength - TCipher.HeaderSize - TCipher.TagSize
		&& TCipher.MaxChunkCount > 0
		&& TCipher.MaxChunkCount <= (long.MaxValue - TCipher.HeaderSize) / (TCipher.ChunkSize + TCipher.TagSize);

	public static int EncryptedChunkSize => TCipher.ChunkSize + TCipher.TagSize;

	public static ChunkSizes Sizes => new(TCipher.HeaderSize, TCipher.ChunkSize, TCipher.TagSize, TCipher.MaxChunkCount);

	/// <summary>
	/// Throws unless the sizes of <typeparamref name="TCipher" /> can be laid out.
	/// </summary>
	public static void ThrowIfUnsupported()
	{
		if (!IsSupported)
		{
			throw new NotSupportedException($"The chunk sizes of {typeof(TCipher)} cannot be laid out.");
		}
	}

	/// <summary>
	/// Throws unless the sizes of <typeparamref name="TCipher" /> can be laid out and <paramref name="key" /> has the right length.
	/// </summary>
	public static void Validate(ReadOnlySpan<byte> key, string paramName)
	{
		ThrowIfUnsupported();
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, TCipher.KeySize, paramName);
	}

	/// <summary>
	/// Gets the message length that an encrypted form of <paramref name="ciphertextLength" /> bytes holds, or fails when no message has an encrypted form of that length.
	/// </summary>
	public static bool TryGetPlaintextLength(long ciphertextLength, out long plaintextLength)
	{
		long chunks = ciphertextLength - TCipher.HeaderSize;
		long fullChunks = Math.DivRem(chunks, EncryptedChunkSize, out long last);

		if (chunks < 0 || last < TCipher.TagSize || fullChunks >= TCipher.MaxChunkCount)
		{
			plaintextLength = 0;
			return false;
		}

		plaintextLength = fullChunks * TCipher.ChunkSize + last - TCipher.TagSize;
		return true;
	}

	[DoesNotReturn]
	public static void Throw(ChunkFailure failure)
	{
		throw new AuthenticationTagMismatchException(failure switch
		{
			ChunkFailure.Truncated => "The ciphertext is truncated or has data after its last chunk.",
			ChunkFailure.ChunkMismatch => "A chunk failed authentication: the ciphertext was modified, reordered or truncated.",
			ChunkFailure.TooManyChunks => "The ciphertext has more chunks than a message may have.",
			_ => throw new ArgumentOutOfRangeException(nameof(failure))
		});
	}
}
