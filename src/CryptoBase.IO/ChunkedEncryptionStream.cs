namespace CryptoBase.IO;

/// <summary>
/// Creates <see cref="ChunkedEncryptionStream{TCipher}" /> instances.
/// </summary>
public static class ChunkedEncryptionStream
{
	/// <summary>
	/// Creates a stream that encrypts a new message into a writable stream.
	/// </summary>
	/// <remarks>The header, with a new random salt, is written before the first chunk. Nothing is written to <paramref name="inner" /> until a chunk is full or <see cref="ChunkedEncryptionStream{TCipher}.FlushFinalChunk" /> is called.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="inner">The writable stream that receives the encrypted message.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message is bound to. It may be empty, and is not stored in the message, so decryption needs the same context.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <returns>The encryption stream.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not writable, or <paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static ChunkedEncryptionStream<TCipher> Create<TCipher>(Stream inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default, bool leaveOpen = false) where TCipher : class, IChunkedCipher<TCipher>
	{
		return ChunkedEncryptionStream<TCipher>.Create(inner, key, context, leaveOpen);
	}
}
