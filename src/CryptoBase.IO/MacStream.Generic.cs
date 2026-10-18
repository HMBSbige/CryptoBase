namespace CryptoBase.IO;

/// <summary>Provides a pass-through stream that appends every byte read from or written to the inner stream to a MAC algorithm.</summary>
/// <remarks>
/// <para>
/// Data is authenticated in the order it passes through, whether it is read or written. Mixing reads and writes on one instance therefore authenticates the interleaving.
/// The stream does not buffer: reads go directly into the caller's buffer and only the bytes actually read are authenticated; writes are authenticated after the inner stream accepts them.
/// </para>
/// <para>
/// The stream is not seekable. The instance owns the MAC algorithm and disposes it on disposal, which erases the key; <c>leaveOpen</c> only controls the inner stream.
/// Callers may still append data such as a header through their own MAC algorithm reference before or between pass-through operations.
/// </para>
/// <para>Instances are not thread safe.</para>
/// </remarks>
/// <typeparam name="TAlgorithm">The MAC algorithm.</typeparam>
public sealed class MacStream<TAlgorithm> : Stream where TAlgorithm : class, IMacAlgorithm<TAlgorithm>
{
	private readonly Stream _inner;
	private readonly TAlgorithm _mac;
	private readonly bool _leaveOpen;
	private bool _disposed;

	/// <summary>Wraps <paramref name="inner" /> so that every byte read from or written to it is appended to <paramref name="mac" />.</summary>
	/// <param name="inner">The stream that data is read from or written to.</param>
	/// <param name="mac">The keyed MAC algorithm that receives the data. This instance takes ownership of it.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open when this instance is disposed.</param>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="mac" /> is <see langword="null" />.</exception>
	public MacStream(Stream inner, TAlgorithm mac, bool leaveOpen = false)
	{
		ArgumentNullException.ThrowIfNull(inner);
		ArgumentNullException.ThrowIfNull(mac);

		_inner = inner;
		_mac = mac;
		_leaveOpen = leaveOpen;
	}

	/// <inheritdoc />
	public override bool CanRead => !_disposed && _inner.CanRead;

	/// <inheritdoc />
	public override bool CanWrite => !_disposed && _inner.CanWrite;

	/// <summary>Gets a value indicating whether the stream supports seeking, which is always <see langword="false" />.</summary>
	public override bool CanSeek => false;

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

	/// <summary>Writes the MAC of the data seen so far without changing the state.</summary>
	/// <param name="destination">The buffer that receives the MAC.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public int GetCurrentMac(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return _mac.GetCurrentMac(destination);
	}

	/// <summary>Writes the MAC of the data seen so far, then resets the message while retaining the key.</summary>
	/// <param name="destination">The buffer that receives the MAC.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public int GetMacAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return _mac.GetMacAndReset(destination);
	}

	/// <summary>Resets the message while retaining the key, discarding the data seen so far.</summary>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_mac.Reset();
	}

	/// <inheritdoc />
	public override int Read(byte[] buffer, int offset, int count)
	{
		ValidateBufferArguments(buffer, offset, count);

		return Read(buffer.AsSpan(offset, count));
	}

	/// <inheritdoc />
	public override int Read(Span<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		int read = _inner.Read(buffer);
		_mac.Append(buffer.Slice(0, read));
		return read;
	}

	/// <inheritdoc />
	public override int ReadByte()
	{
		Span<byte> buffer = stackalloc byte[1];
		return Read(buffer) is 0 ? -1 : buffer[0];
	}

	/// <inheritdoc />
	public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		ValidateBufferArguments(buffer, offset, count);

		return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
	}

	/// <inheritdoc />
	public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		ValueTask<int> task = _inner.ReadAsync(buffer, cancellationToken);

		if (task.IsCompletedSuccessfully)
		{
			int read = task.Result;
			_mac.Append(buffer.Span.Slice(0, read));
			return ValueTask.FromResult(read);
		}

		return AwaitReadAsync(task, buffer);
	}

	/// <inheritdoc />
	public override void Write(byte[] buffer, int offset, int count)
	{
		ValidateBufferArguments(buffer, offset, count);

		Write(buffer.AsSpan(offset, count));
	}

	/// <inheritdoc />
	public override void Write(ReadOnlySpan<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_inner.Write(buffer);
		_mac.Append(buffer);
	}

	/// <inheritdoc />
	public override void WriteByte(byte value)
	{
		Span<byte> buffer = stackalloc byte[1];
		buffer[0] = value;
		Write(buffer);
	}

	/// <inheritdoc />
	public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		ValidateBufferArguments(buffer, offset, count);

		return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
	}

	/// <inheritdoc />
	public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		ValueTask task = _inner.WriteAsync(buffer, cancellationToken);

		if (task.IsCompletedSuccessfully)
		{
			task.GetAwaiter().GetResult();
			_mac.Append(buffer.Span);
			return ValueTask.CompletedTask;
		}

		return AwaitWriteAsync(task, buffer);
	}

	/// <inheritdoc />
	public override void Flush()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_inner.Flush();
	}

	/// <inheritdoc />
	public override Task FlushAsync(CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return _inner.FlushAsync(cancellationToken);
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

	/// <summary>Disposes the MAC algorithm and, unless <c>leaveOpen</c> was specified, the inner stream.</summary>
	/// <param name="disposing"><see langword="true" /> when called from <see cref="Stream.Dispose()" />.</param>
	protected override void Dispose(bool disposing)
	{
		if (disposing && !_disposed)
		{
			_disposed = true;
			_mac.Dispose();

			if (!_leaveOpen)
			{
				_inner.Dispose();
			}
		}

		base.Dispose(disposing);
	}

	/// <summary>Disposes the MAC algorithm and, unless <c>leaveOpen</c> was specified, asynchronously disposes the inner stream.</summary>
	/// <returns>A task that represents the asynchronous dispose operation.</returns>
	public override ValueTask DisposeAsync()
	{
		if (_disposed)
		{
			return ValueTask.CompletedTask;
		}

		_disposed = true;
		_mac.Dispose();
		return _leaveOpen ? ValueTask.CompletedTask : _inner.DisposeAsync();
	}

	private async ValueTask<int> AwaitReadAsync(ValueTask<int> task, Memory<byte> buffer)
	{
		int read = await task.ConfigureAwait(false);
		_mac.Append(buffer.Span.Slice(0, read));
		return read;
	}

	private async ValueTask AwaitWriteAsync(ValueTask task, ReadOnlyMemory<byte> buffer)
	{
		await task.ConfigureAwait(false);
		_mac.Append(buffer.Span);
	}
}
