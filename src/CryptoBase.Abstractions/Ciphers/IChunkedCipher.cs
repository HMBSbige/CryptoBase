using System.Security.Cryptography;

namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines chunked authenticated encryption, such as c2sp.org/chunked-encryption, for one message at a time.
/// </summary>
/// <remarks>
/// <para>
/// An encrypted message is a header of <see cref="HeaderSize" /> bytes followed by its encrypted chunks. Every chunk but the last holds exactly <see cref="ChunkSize" /> plaintext bytes, and the last holds fewer, possibly none, so a message whose length is a multiple of <see cref="ChunkSize" /> ends with an empty chunk. An encrypted chunk is its ciphertext, as long as its plaintext, followed by a <see cref="TagSize" />-byte tag. Chunks are numbered from zero, and each chunk is authenticated with its index, so a decrypter that follows these rules detects reordered, missing, truncated and appended chunks.
/// </para>
/// <para>
/// An instance holds the keys of one message, derived from the input key, the header and the context. The chunk methods take the index and do not know which chunk is the last; the caller applies the chunking rules. Disposal erases the keys and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IChunkedCipher<out TSelf> : IDisposable where TSelf : IChunkedCipher<TSelf>, allows ref struct
{
	/// <summary>
	/// Gets the input key size, in bytes.
	/// </summary>
	static abstract int KeySize { get; }

	/// <summary>
	/// Gets the header size, in bytes.
	/// </summary>
	static abstract int HeaderSize { get; }

	/// <summary>
	/// Gets the plaintext size of every chunk but the last, in bytes.
	/// </summary>
	static abstract int ChunkSize { get; }

	/// <summary>
	/// Gets the size of the tag that follows the ciphertext of each chunk, in bytes.
	/// </summary>
	static abstract int TagSize { get; }

	/// <summary>
	/// Gets the most chunks a message may have, including its last chunk.
	/// </summary>
	static abstract long MaxChunkCount { get; }

	/// <summary>
	/// Creates an instance that encrypts a new message and writes the message header.
	/// </summary>
	/// <param name="key">The input key, <see cref="KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message is bound to. It may be empty, and is not stored in the message.</param>
	/// <param name="header">The buffer that receives the header in its first <see cref="HeaderSize" /> bytes.</param>
	/// <returns>The instance.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> has the wrong length, or <paramref name="header" /> is too short.</exception>
	static abstract TSelf CreateEncryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped Span<byte> header);

	/// <summary>
	/// Creates an instance that decrypts the message that starts with <paramref name="header" />, after checking that the header matches the key and context.
	/// </summary>
	/// <param name="key">The input key, <see cref="KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="header">The message header, exactly <see cref="HeaderSize" /> bytes long.</param>
	/// <returns>The instance.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> or <paramref name="header" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The header does not match the key and context: either is wrong, or the header was modified.</exception>
	static abstract TSelf CreateDecryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped ReadOnlySpan<byte> header);

	/// <summary>
	/// Encrypts the chunk numbered <paramref name="index" /> and appends its tag.
	/// </summary>
	/// <remarks>
	/// Encrypt each index at most once with an instance: a second plaintext under the same index exposes both. To change any part of a message, encrypt the whole message again with a new instance, which writes a new header.
	/// If <paramref name="plaintext" /> and <paramref name="ciphertext" /> overlap, they must start at the same byte.
	/// </remarks>
	/// <param name="index">The chunk index, from zero to <see cref="MaxChunkCount" /> - 1.</param>
	/// <param name="plaintext">The chunk plaintext, at most <see cref="ChunkSize" /> bytes long.</param>
	/// <param name="ciphertext">The buffer that receives the ciphertext and then the tag; at least <see cref="TagSize" /> bytes longer than <paramref name="plaintext" />.</param>
	/// <exception cref="ArgumentException">A buffer has the wrong length, or the buffers overlap at different starts.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="index" /> is out of range.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void EncryptChunk(long index, scoped ReadOnlySpan<byte> plaintext, scoped Span<byte> ciphertext);

	/// <summary>
	/// Authenticates the chunk numbered <paramref name="index" /> and decrypts it.
	/// </summary>
	/// <remarks>If <paramref name="ciphertext" /> and <paramref name="plaintext" /> overlap, they must start at the same byte.</remarks>
	/// <param name="index">The chunk index, from zero to <see cref="MaxChunkCount" /> - 1.</param>
	/// <param name="ciphertext">The encrypted chunk: its ciphertext and then the tag, from <see cref="TagSize" /> to <see cref="ChunkSize" /> + <see cref="TagSize" /> bytes long.</param>
	/// <param name="plaintext">The buffer that receives the plaintext; at least as long as <paramref name="ciphertext" /> without its tag.</param>
	/// <returns><see langword="false" /> on authentication failure, clearing the plaintext-length output prefix; <see langword="true" /> on success.</returns>
	/// <exception cref="ArgumentException">A buffer has the wrong length, or the buffers overlap at different starts.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="index" /> is out of range.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	bool TryDecryptChunk(long index, scoped ReadOnlySpan<byte> ciphertext, scoped Span<byte> plaintext);
}
