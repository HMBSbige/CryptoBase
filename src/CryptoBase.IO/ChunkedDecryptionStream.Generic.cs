using CryptoBase.IO.Chunked;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.IO;

/// <summary>
/// Provides streaming chunked authenticated decryption, such as of Cobblestone, from an inner stream.
/// </summary>
/// <typeparam name="TCipher">The chunked cipher.</typeparam>
/// <remarks>
/// <para>
/// The stream is read-only and not seekable, and reads the inner stream from its current position to its end. The header is read and checked against the key and context when the stream is created, before any chunk is decrypted.
/// </para>
/// <para>
/// A chunk becomes readable only once it has been read whole and authenticated, so a read waits for a full chunk or the end of the inner stream. The end of the inner stream marks the last chunk, which must be shorter than a full chunk; a read into a non-empty buffer returns zero, the end of the message, only after the last chunk has been authenticated. A read into an empty buffer returns zero without reading on.
/// </para>
/// <para>
/// Plaintext read before an error is authentic, but it may belong to a message that turns out truncated or modified further on, so act on the message only once a read into a non-empty buffer has returned zero. Once a read fails with <see cref="AuthenticationTagMismatchException" />, every later read fails the same way.
/// </para>
/// <para>
/// The instance owns the cipher of the message and disposes it; <c>leaveOpen</c> controls only the inner stream.
/// Instances are not thread-safe.
/// </para>
/// </remarks>
public sealed class ChunkedDecryptionStream<TCipher> : Stream where TCipher : class, IChunkedCipher<TCipher>
{
	private readonly Stream _inner;
	private readonly TCipher _cipher;
	private readonly bool _leaveOpen;
	private readonly ChunkSizes _sizes;

	// The current encrypted chunk as it is read, then its plaintext once it is authenticated and decrypted in place.
	private readonly byte[] _buffer;

	// The encrypted bytes of the current chunk read so far.
	private int _filled;
	private int _plaintextOffset;
	private int _plaintextEnd;
	private long _chunkIndex;
	private bool _endOfMessage;
	private ChunkFailure _failure;
	private bool _disposed;

	private ChunkedDecryptionStream(Stream inner, TCipher cipher, byte[] buffer, bool leaveOpen)
	{
		_inner = inner;
		_cipher = cipher;
		_buffer = buffer;
		_leaveOpen = leaveOpen;
		_sizes = ChunkLayout<TCipher>.Sizes;
	}

	internal static ChunkedDecryptionStream<TCipher> Create(Stream inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, bool leaveOpen)
	{
		ValidateInner(inner);
		ChunkLayout<TCipher>.Validate(key, nameof(key));

		byte[] buffer = AllocateBuffer();
		Span<byte> header = buffer.AsSpan(0, TCipher.HeaderSize);

		if (inner.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length)
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.Truncated);
		}

		return new ChunkedDecryptionStream<TCipher>(inner, TCipher.CreateDecryptor(key, context, header), buffer, leaveOpen);
	}

	internal static Task<ChunkedDecryptionStream<TCipher>> CreateAsync(Stream inner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context, bool leaveOpen, CancellationToken cancellationToken)
	{
		ValidateInner(inner);
		ChunkLayout<TCipher>.Validate(key.Span, nameof(key));

		if (cancellationToken.IsCancellationRequested)
		{
			return Task.FromCanceled<ChunkedDecryptionStream<TCipher>>(cancellationToken);
		}

		return CreateCoreAsync(inner, key, context, leaveOpen, cancellationToken);
	}

	/// <summary>
	/// Gets a value that indicates whether the stream supports reading.
	/// </summary>
	public override bool CanRead => !_disposed;

	/// <summary>
	/// Gets a value that indicates whether the stream supports seeking, which is always <see langword="false" />.
	/// </summary>
	public override bool CanSeek => false;

	/// <summary>
	/// Gets a value that indicates whether the stream supports writing, which is always <see langword="false" />.
	/// </summary>
	public override bool CanWrite => false;

	/// <summary>Not supported.</summary>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override long Length => throw new NotSupportedException();

	/// <summary>Not supported.</summary>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override long Position
	{
		get => throw new NotSupportedException();
		set => throw new NotSupportedException();
	}

	/// <inheritdoc />
	public override int Read(byte[] buffer, int offset, int count)
	{
		ValidateBufferArguments(buffer, offset, count);
		return Read(buffer.AsSpan(offset, count));
	}

	/// <inheritdoc />
	/// <remarks>Returns at most one chunk of plaintext per call.</remarks>
	/// <exception cref="AuthenticationTagMismatchException">The message is truncated or has data after its last chunk, a chunk was modified or reordered, or the message has more chunks than <typeparamref name="TCipher" /> allows.</exception>
	public override int Read(Span<byte> buffer)
	{
		ThrowIfNotReadable();

		if (buffer.IsEmpty)
		{
			return 0;
		}

		int copied = CopyPlaintext(buffer);

		if (copied > 0 || _endOfMessage)
		{
			return copied;
		}

		while (_filled < _sizes.EncryptedChunkSize)
		{
			int read = _inner.Read(_buffer.AsSpan(_filled, _sizes.EncryptedChunkSize - _filled));

			if (read is 0)
			{
				break;
			}

			_filled += read;
		}

		return DecryptChunk(buffer);
	}

	/// <inheritdoc />
	public override int ReadByte()
	{
		byte value = 0;
		return Read(new Span<byte>(ref value)) is 0 ? -1 : value;
	}

	/// <inheritdoc />
	public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		ValidateBufferArguments(buffer, offset, count);
		return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
	}

	/// <inheritdoc />
	/// <remarks>Returns at most one chunk of plaintext per call.</remarks>
	/// <exception cref="AuthenticationTagMismatchException">The message is truncated or has data after its last chunk, a chunk was modified or reordered, or the message has more chunks than <typeparamref name="TCipher" /> allows.</exception>
	public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ThrowIfNotReadable();

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<int>(cancellationToken);
		}

		if (buffer.IsEmpty)
		{
			return ValueTask.FromResult(0);
		}

		int copied = CopyPlaintext(buffer.Span);

		if (copied > 0 || _endOfMessage)
		{
			return ValueTask.FromResult(copied);
		}

		return ReadChunkAsync(buffer, cancellationToken);
	}

	/// <summary>
	/// Does nothing, as the stream is read-only.
	/// </summary>
	public override void Flush()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
	}

	/// <summary>Not supported.</summary>
	/// <param name="buffer">Unused.</param>
	/// <param name="offset">Unused.</param>
	/// <param name="count">Unused.</param>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override void Write(byte[] buffer, int offset, int count)
	{
		throw new NotSupportedException();
	}

	/// <summary>Not supported.</summary>
	/// <param name="offset">Unused.</param>
	/// <param name="origin">Unused.</param>
	/// <returns>Never returns.</returns>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override long Seek(long offset, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

	/// <summary>Not supported.</summary>
	/// <param name="value">Unused.</param>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override void SetLength(long value)
	{
		throw new NotSupportedException();
	}

	/// <summary>
	/// Erases the buffered plaintext and disposes the cipher and, unless <c>leaveOpen</c> was set, asynchronously disposes the inner stream.
	/// </summary>
	/// <returns>A task that represents the asynchronous dispose operation.</returns>
	public override ValueTask DisposeAsync()
	{
		if (_disposed)
		{
			return ValueTask.CompletedTask;
		}

		Release();
		return _leaveOpen ? ValueTask.CompletedTask : _inner.DisposeAsync();
	}

	/// <summary>
	/// Erases the buffered plaintext and disposes the cipher and, unless <c>leaveOpen</c> was set, the inner stream.
	/// </summary>
	/// <param name="disposing"><see langword="true" /> when called from <see cref="Stream.Dispose()" />.</param>
	protected override void Dispose(bool disposing)
	{
		if (disposing && !_disposed)
		{
			Release();

			if (!_leaveOpen)
			{
				_inner.Dispose();
			}
		}

		base.Dispose(disposing);
	}

	private static async Task<ChunkedDecryptionStream<TCipher>> CreateCoreAsync(Stream inner, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> context, bool leaveOpen, CancellationToken cancellationToken)
	{
		byte[] buffer = AllocateBuffer();
		Memory<byte> header = buffer.AsMemory(0, TCipher.HeaderSize);

		if (await inner.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < header.Length)
		{
			ChunkLayout<TCipher>.Throw(ChunkFailure.Truncated);
		}

		return new ChunkedDecryptionStream<TCipher>(inner, TCipher.CreateDecryptor(key.Span, context.Span, header.Span), buffer, leaveOpen);
	}

	private async ValueTask<int> ReadChunkAsync(Memory<byte> buffer, CancellationToken cancellationToken)
	{
		while (_filled < _sizes.EncryptedChunkSize)
		{
			int read = await _inner.ReadAsync(_buffer.AsMemory(_filled, _sizes.EncryptedChunkSize - _filled), cancellationToken).ConfigureAwait(false);

			if (read is 0)
			{
				break;
			}

			_filled += read;
		}

		return DecryptChunk(buffer.Span);
	}

	private int CopyPlaintext(Span<byte> destination)
	{
		int length = Math.Min(_plaintextEnd - _plaintextOffset, destination.Length);
		_buffer.AsSpan(_plaintextOffset, length).CopyTo(destination);
		_plaintextOffset += length;
		return length;
	}

	/// <summary>
	/// Authenticates and decrypts the chunk read so far, which is the last one unless it is full, and returns its plaintext up to the length of <paramref name="destination" />.
	/// </summary>
	private int DecryptChunk(Span<byte> destination)
	{
		bool last = _filled < _sizes.EncryptedChunkSize;

		if (_filled < _sizes.TagSize)
		{
			Fail(ChunkFailure.Truncated);
		}

		if (_chunkIndex >= _sizes.MaxChunkCount)
		{
			Fail(ChunkFailure.TooManyChunks);
		}

		int length = _filled - _sizes.TagSize;

		// A chunk that fits goes straight to the caller; the cipher clears it there if authentication fails.
		bool direct = destination.Length >= length;

		if (!_cipher.TryDecryptChunk(_chunkIndex, _buffer.AsSpan(0, _filled), direct ? destination : _buffer))
		{
			Fail(ChunkFailure.ChunkMismatch);
		}

		++_chunkIndex;
		_filled = 0;
		_endOfMessage = last;

		if (direct)
		{
			return length;
		}

		_plaintextOffset = 0;
		_plaintextEnd = length;
		return CopyPlaintext(destination);
	}

	[DoesNotReturn]
	private void Fail(ChunkFailure failure)
	{
		_failure = failure;
		CryptographicOperations.ZeroMemory(_buffer);
		ChunkLayout<TCipher>.Throw(failure);
	}

	private void Release()
	{
		_disposed = true;
		CryptographicOperations.ZeroMemory(_buffer);
		_cipher.Dispose();
	}

	private void ThrowIfNotReadable()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_failure is not ChunkFailure.None)
		{
			ChunkLayout<TCipher>.Throw(_failure);
		}
	}

	private static void ValidateInner(Stream inner)
	{
		ArgumentNullException.ThrowIfNull(inner);

		if (!inner.CanRead)
		{
			throw new ArgumentException("The stream must support reading.", nameof(inner));
		}
	}

	private static byte[] AllocateBuffer()
	{
		return GC.AllocateUninitializedArray<byte>(Math.Max(TCipher.HeaderSize, ChunkLayout<TCipher>.EncryptedChunkSize));
	}
}
