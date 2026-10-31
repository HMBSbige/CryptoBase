using CryptoBase.IO.Storage;

namespace CryptoBase.IO;

/// <summary>
/// Creates <see cref="ChunkedRandomAccess{TCipher}" /> instances.
/// </summary>
public static class ChunkedRandomAccess
{
	/// <summary>
	/// Creates authenticated positional reads of the encrypted message in a file.
	/// </summary>
	/// <remarks>Checks the header against the key and context, then authenticates the last chunk, before the instance is returned. If the method throws, <paramref name="handle" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="handle">The readable file handle whose file holds exactly the encrypted message.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="handle" /> open on disposal.</param>
	/// <returns>The positional reads.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="handle" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The file is truncated or extended, the header does not match the key and context, or the last chunk was modified.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static ChunkedRandomAccess<TCipher> Create<TCipher>(SafeFileHandle handle, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default, bool leaveOpen = false) where TCipher : class, IChunkedCipher<TCipher>
	{
		ArgumentNullException.ThrowIfNull(handle);
		return ChunkedRandomAccess<TCipher>.Create(new FileHandleStorage(handle), handle, key, context, leaveOpen);
	}

	/// <summary>
	/// Creates authenticated positional reads of the encrypted message in a seekable stream.
	/// </summary>
	/// <remarks>Checks the header against the key and context, then authenticates the last chunk, before the instance is returned. Each access positions the stream first, so its position is not preserved. If the method throws, <paramref name="inner" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="inner">The readable, seekable stream that holds exactly the encrypted message.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <returns>The positional reads.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not readable and seekable, or <paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The stream is truncated or extended, the header does not match the key and context, or the last chunk was modified.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static ChunkedRandomAccess<TCipher> Create<TCipher>(Stream inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context = default, bool leaveOpen = false) where TCipher : class, IChunkedCipher<TCipher>
	{
		ValidateInner(inner);
		return ChunkedRandomAccess<TCipher>.Create(new SeekableStreamStorage(inner), inner, key, context, leaveOpen);
	}

	/// <summary>
	/// Asynchronously creates authenticated positional reads of the encrypted message in a file.
	/// </summary>
	/// <remarks>Checks the header against the key and context, then authenticates the last chunk, before the instance is returned. The key and context must not change until the task completes. If the task fails, <paramref name="handle" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="handle">The readable file handle whose file holds exactly the encrypted message.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="handle" /> open on disposal.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A task whose result is the positional reads.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="handle" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The file is truncated or extended, the header does not match the key and context, or the last chunk was modified.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static Task<ChunkedRandomAccess<TCipher>> CreateAsync<TCipher>(SafeFileHandle handle, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context = default, bool leaveOpen = false, CancellationToken cancellationToken = default) where TCipher : class, IChunkedCipher<TCipher>
	{
		ArgumentNullException.ThrowIfNull(handle);
		return ChunkedRandomAccess<TCipher>.CreateAsync(new FileHandleStorage(handle), handle, key, context, leaveOpen, cancellationToken);
	}

	/// <summary>
	/// Asynchronously creates authenticated positional reads of the encrypted message in a seekable stream.
	/// </summary>
	/// <remarks>Checks the header against the key and context, then authenticates the last chunk, before the instance is returned. Each access positions the stream first, so its position is not preserved. The key and context must not change until the task completes. If the task fails, <paramref name="inner" /> is not disposed.</remarks>
	/// <typeparam name="TCipher">The chunked cipher, such as <c>Cobblestone128Cipher</c>.</typeparam>
	/// <param name="inner">The readable, seekable stream that holds exactly the encrypted message.</param>
	/// <param name="key">The input key, <see cref="IChunkedCipher{TSelf}.KeySize" /> bytes long.</param>
	/// <param name="context">The context that the message was encrypted with.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A task whose result is the positional reads.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not readable and seekable, or <paramref name="key" /> has the wrong length.</exception>
	/// <exception cref="AuthenticationTagMismatchException">The stream is truncated or extended, the header does not match the key and context, or the last chunk was modified.</exception>
	/// <exception cref="NotSupportedException">The sizes of <typeparamref name="TCipher" /> cannot be laid out.</exception>
	public static Task<ChunkedRandomAccess<TCipher>> CreateAsync<TCipher>(Stream inner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context = default, bool leaveOpen = false, CancellationToken cancellationToken = default) where TCipher : class, IChunkedCipher<TCipher>
	{
		ValidateInner(inner);
		return ChunkedRandomAccess<TCipher>.CreateAsync(new SeekableStreamStorage(inner), inner, key, context, leaveOpen, cancellationToken);
	}

	private static void ValidateInner(Stream inner)
	{
		ArgumentNullException.ThrowIfNull(inner);

		if (!inner.CanRead || !inner.CanSeek)
		{
			throw new ArgumentException("The stream must support reading and seeking.", nameof(inner));
		}
	}
}
