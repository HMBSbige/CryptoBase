namespace CryptoBase.IO;

/// <summary>
/// Creates <see cref="ChunkedDecryptionStream{TCipher}" /> instances.
/// </summary>
public static class ChunkedDecryptionStream
{
	/// <summary>
	/// Reads the message header from a readable stream and creates a stream that decrypts the message.
	/// </summary>
	/// <remarks>The header is checked against the key and context before the stream is returned. If the method throws, <paramref name="inner" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="inner">The readable stream that holds the encrypted message from its current position to its end.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <returns>The decryption stream.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not readable, or <paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The stream ends inside the header, or the header does not match the key and context.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static ChunkedDecryptionStream<TCipher> Create<TCipher>(Stream inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default, bool leaveOpen = false) where TCipher : class, IChunkedCipher<TCipher>
	{
		return ChunkedDecryptionStream<TCipher>.Create(inner, key, context, leaveOpen);
	}

	/// <summary>
	/// Asynchronously reads the message header from a readable stream and creates a stream that decrypts the message.
	/// </summary>
	/// <remarks>The header is checked against the key and context before the stream is returned. The key and context must not change until the task completes. If the task fails, <paramref name="inner" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="inner">The readable stream that holds the encrypted message from its current position to its end.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A task whose result is the decryption stream.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not readable, or <paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The stream ends inside the header, or the header does not match the key and context.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static Task<ChunkedDecryptionStream<TCipher>> CreateAsync<TCipher>(Stream inner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context = default, bool leaveOpen = false, CancellationToken cancellationToken = default) where TCipher : class, IChunkedCipher<TCipher>
	{
		return ChunkedDecryptionStream<TCipher>.CreateAsync(inner, key, context, leaveOpen, cancellationToken);
	}
}
