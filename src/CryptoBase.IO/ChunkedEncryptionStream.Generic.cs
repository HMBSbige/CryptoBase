using CryptoBase.IO.Chunked;

namespace CryptoBase.IO;

/// <summary>
/// Provides streaming chunked authenticated encryption, such as Cobblestone, into an inner stream.
/// </summary>
/// <typeparam name="TCipher">The chunked cipher.</typeparam>
/// <remarks>
/// <para>
/// The stream is write-only and not seekable. It buffers one chunk of plaintext and writes each chunk to the inner stream as soon as it is full, after the message header for the first one. Each chunk reaches the inner stream in a single write.
/// </para>
/// <para>
/// The message is complete only once <see cref="FlushFinalChunk" /> or <see cref="FlushFinalChunkAsync" /> writes the last chunk, which is shorter than a full chunk and may be empty. Disposal does not write it: it discards any buffered plaintext and leaves the ciphertext without a last chunk, which decryption rejects as truncated, so that a write abandoned partway, such as by an exception, cannot leave a valid shorter message. <see cref="Flush" /> only flushes the inner stream, because a chunk cannot be written before it is full or the message ends.
/// </para>
/// <para>
/// A write to the inner stream that fails leaves the ciphertext in an unknown state, so later writes and <see cref="FlushFinalChunk" /> throw <see cref="InvalidOperationException" />.
/// </para>
/// <para>
/// The instance owns the cipher of the message and disposes it; <c>leaveOpen</c> controls only the inner stream.
/// Instances are not thread-safe.
/// </para>
/// </remarks>
public sealed class ChunkedEncryptionStream<TCipher> : Stream where TCipher : class, IChunkedCipher<TCipher>
{
	private readonly Stream _inner;
	private readonly TCipher _cipher;
	private readonly bool _leaveOpen;
	private readonly ChunkSizes _sizes;

	// The header, then the plaintext of the current chunk, which is encrypted in place once complete, then its tag.
	private readonly byte[] _buffer;

	// The length of the current chunk.
	private int _buffered;
	private long _chunkIndex;
	private bool _faulted;
	private bool _disposed;

	private ChunkedEncryptionStream(Stream inner, TCipher cipher, byte[] buffer, bool leaveOpen)
	{
		_inner = inner;
		_cipher = cipher;
		_buffer = buffer;
		_leaveOpen = leaveOpen;
		_sizes = ChunkLayout<TCipher>.Sizes;
	}

	internal static ChunkedEncryptionStream<TCipher> Create(Stream inner, ReadOnlySpan<byte> key, ReadOnlySpan<byte> context, bool leaveOpen)
	{
		ValidateInner(inner);
		ChunkLayout<TCipher>.Validate(key, nameof(key));

		byte[] buffer = AllocateBuffer();
		return new ChunkedEncryptionStream<TCipher>(inner, TCipher.CreateEncryptor(key, context, buffer.AsSpan(0, TCipher.HeaderSize)), buffer, leaveOpen);
	}

	/// <summary>
	/// Gets a value that indicates whether the last chunk has been written, which completes the message.
	/// </summary>
	public bool HasFlushedFinalChunk { get; private set; }

	/// <summary>
	/// Gets a value that indicates whether the stream supports reading, which is always <see langword="false" />.
	/// </summary>
	public override bool CanRead => false;

	/// <summary>
	/// Gets a value that indicates whether the stream supports seeking, which is always <see langword="false" />.
	/// </summary>
	public override bool CanSeek => false;

	/// <inheritdoc />
	public override bool CanWrite => !_disposed;

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
	public override void Write(byte[] buffer, int offset, int count)
	{
		ValidateBufferArguments(buffer, offset, count);
		Write(buffer.AsSpan(offset, count));
	}

	/// <inheritdoc />
	/// <exception cref="IOException">The message would exceed the largest length that <typeparamref name="TCipher" /> allows.</exception>
	/// <exception cref="InvalidOperationException">The last chunk has been written, or an earlier write failed.</exception>
	public override void Write(ReadOnlySpan<byte> buffer)
	{
		ThrowIfNotWritable(buffer.Length);

		try
		{
			while (!buffer.IsEmpty)
			{
				if (PrepareChunk(buffer, out int consumed))
				{
					_inner.Write(GetPendingChunk().Span);
					CompleteChunk();
				}

				buffer = buffer.Slice(consumed);
			}
		}
		catch
		{
			Fault();
			throw;
		}
	}

	/// <inheritdoc />
	public override void WriteByte(byte value)
	{
		Write(new ReadOnlySpan<byte>(in value));
	}

	/// <inheritdoc />
	public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		ValidateBufferArguments(buffer, offset, count);
		return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
	}

	/// <inheritdoc />
	/// <exception cref="IOException">The message would exceed the largest length that <typeparamref name="TCipher" /> allows.</exception>
	/// <exception cref="InvalidOperationException">The last chunk has been written, or an earlier write failed.</exception>
	public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ThrowIfNotWritable(buffer.Length);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled(cancellationToken);
		}

		// A write that leaves the chunk incomplete only buffers.
		if (buffer.Length < _sizes.ChunkSize - _buffered)
		{
			buffer.Span.CopyTo(_buffer.AsSpan(_sizes.HeaderSize + _buffered));
			_buffered += buffer.Length;
			return ValueTask.CompletedTask;
		}

		return WriteCoreAsync(buffer, cancellationToken);
	}

	/// <summary>
	/// Encrypts the buffered plaintext as the last chunk and writes it to the inner stream, which completes the message.
	/// </summary>
	/// <remarks>The last chunk is written even if it is empty. The inner stream is not flushed.</remarks>
	/// <exception cref="InvalidOperationException">The last chunk has already been written, or an earlier write failed.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public void FlushFinalChunk()
	{
		ThrowIfNotWritable(0);

		try
		{
			EncryptChunk(_buffer.AsSpan(_sizes.HeaderSize, _buffered));
			_inner.Write(GetPendingChunk().Span);
			HasFlushedFinalChunk = true;
		}
		catch
		{
			Fault();
			throw;
		}
	}

	/// <summary>
	/// Asynchronously encrypts the buffered plaintext as the last chunk and writes it to the inner stream, which completes the message.
	/// </summary>
	/// <remarks>The last chunk is written even if it is empty. The inner stream is not flushed.</remarks>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A value task that completes when the last chunk is written.</returns>
	/// <exception cref="InvalidOperationException">The last chunk has already been written, or an earlier write failed.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public ValueTask FlushFinalChunkAsync(CancellationToken cancellationToken = default)
	{
		ThrowIfNotWritable(0);

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled(cancellationToken);
		}

		return FlushFinalChunkCoreAsync(cancellationToken);
	}

	/// <inheritdoc />
	/// <remarks>Flushes the inner stream only: buffered plaintext stays buffered until its chunk is complete.</remarks>
	public override void Flush()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_inner.Flush();
	}

	/// <inheritdoc />
	/// <remarks>Flushes the inner stream only: buffered plaintext stays buffered until its chunk is complete.</remarks>
	public override Task FlushAsync(CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _inner.FlushAsync(cancellationToken);
	}

	/// <summary>Not supported.</summary>
	/// <param name="buffer">Unused.</param>
	/// <param name="offset">Unused.</param>
	/// <param name="count">Unused.</param>
	/// <returns>Never returns.</returns>
	/// <exception cref="NotSupportedException">Always.</exception>
	public override int Read(byte[] buffer, int offset, int count)
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
	/// <remarks>Does not write the last chunk: without <see cref="FlushFinalChunkAsync" />, the message stays incomplete.</remarks>
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
	/// <remarks>Does not write the last chunk: without <see cref="FlushFinalChunk" />, the message stays incomplete.</remarks>
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

	private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
	{
		try
		{
			while (!buffer.IsEmpty)
			{
				if (PrepareChunk(buffer.Span, out int consumed))
				{
					await _inner.WriteAsync(GetPendingChunk(), cancellationToken).ConfigureAwait(false);
					CompleteChunk();
				}

				buffer = buffer.Slice(consumed);
			}
		}
		catch
		{
			Fault();
			throw;
		}
	}

	private async ValueTask FlushFinalChunkCoreAsync(CancellationToken cancellationToken)
	{
		try
		{
			EncryptChunk(_buffer.AsSpan(_sizes.HeaderSize, _buffered));
			await _inner.WriteAsync(GetPendingChunk(), cancellationToken).ConfigureAwait(false);
			HasFlushedFinalChunk = true;
		}
		catch
		{
			Fault();
			throw;
		}
	}

	/// <summary>
	/// Takes plaintext from <paramref name="source" /> into the current chunk, and encrypts the chunk once it is full.
	/// </summary>
	/// <returns><see langword="true" /> when the chunk is encrypted and waits to be written.</returns>
	private bool PrepareChunk(ReadOnlySpan<byte> source, out int consumed)
	{
		if (_buffered is 0 && source.Length >= _sizes.ChunkSize)
		{
			consumed = _sizes.ChunkSize;
			EncryptChunk(source.Slice(0, consumed));
			return true;
		}

		consumed = Math.Min(_sizes.ChunkSize - _buffered, source.Length);
		source.Slice(0, consumed).CopyTo(_buffer.AsSpan(_sizes.HeaderSize + _buffered));
		_buffered += consumed;

		if (_buffered < _sizes.ChunkSize)
		{
			return false;
		}

		EncryptChunk(_buffer.AsSpan(_sizes.HeaderSize, _buffered));
		return true;
	}

	/// <summary>
	/// Encrypts <paramref name="plaintext" />, from the caller or in place, into the current chunk.
	/// </summary>
	private void EncryptChunk(ReadOnlySpan<byte> plaintext)
	{
		_cipher.EncryptChunk(_chunkIndex, plaintext, _buffer.AsSpan(_sizes.HeaderSize, plaintext.Length + _sizes.TagSize));
		_buffered = plaintext.Length;
	}

	/// <summary>
	/// Gets the encrypted current chunk, after the header if it is the first chunk.
	/// </summary>
	private ReadOnlyMemory<byte> GetPendingChunk()
	{
		int start = _chunkIndex is 0 ? 0 : _sizes.HeaderSize;
		return _buffer.AsMemory(start, _sizes.HeaderSize - start + _buffered + _sizes.TagSize);
	}

	private void CompleteChunk()
	{
		_buffered = 0;
		++_chunkIndex;
	}

	/// <summary>
	/// Marks the stream unusable after a failure and erases the plaintext that the buffer may hold.
	/// </summary>
	private void Fault()
	{
		_faulted = true;
		CryptographicOperations.ZeroMemory(_buffer);
	}

	private void Release()
	{
		_disposed = true;
		CryptographicOperations.ZeroMemory(_buffer);
		_cipher.Dispose();
	}

	private void ThrowIfNotWritable(int count)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_faulted)
		{
			throw new InvalidOperationException("An earlier write failed, so the message is incomplete.");
		}

		if (HasFlushedFinalChunk)
		{
			throw new InvalidOperationException("The last chunk has been written, so the message is complete.");
		}

		if (count > _sizes.MaxMessageLength - (_chunkIndex * _sizes.ChunkSize + _buffered))
		{
			throw new IOException("The message would exceed the largest length that the cipher allows.");
		}
	}

	private static void ValidateInner(Stream inner)
	{
		ArgumentNullException.ThrowIfNull(inner);

		if (!inner.CanWrite)
		{
			throw new ArgumentException("The stream must support writing.", nameof(inner));
		}
	}

	private static byte[] AllocateBuffer()
	{
		return GC.AllocateUninitializedArray<byte>(TCipher.HeaderSize + ChunkLayout<TCipher>.EncryptedChunkSize);
	}
}
