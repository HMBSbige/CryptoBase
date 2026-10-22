namespace CryptoBase.IO;

/// <summary>Provides a pass-through stream that appends every byte read from or written to the inner stream to an incremental algorithm.</summary>
/// <remarks>
/// <para>
/// Data is appended in the order it passes through, whether it is read or written. Mixing reads and writes on one instance therefore appends the interleaving.
/// The stream does not buffer: reads go directly into the caller's buffer and only the bytes actually read are appended; writes are appended after the inner stream accepts them.
/// A write buffer must therefore not overlap the inner stream's storage, such as the array returned by <see cref="MemoryStream.GetBuffer" />; otherwise the appended bytes may differ from the written ones.
/// </para>
/// <para>
/// The stream is not seekable. The instance owns the algorithm and disposes it on disposal; <c>leaveOpen</c> only controls the inner stream.
/// Callers may still append data such as a header through their own algorithm reference before or between pass-through operations.
/// </para>
/// <para>Instances are not thread safe.</para>
/// </remarks>
/// <typeparam name="TAlgorithm">The algorithm.</typeparam>
public abstract class AppendStream<TAlgorithm> : Stream where TAlgorithm : class, IIncrementalAlgorithm, IDisposable
{
	private readonly Stream _inner;
	private readonly TAlgorithm _algorithm;
	private readonly bool _leaveOpen;
	private bool _disposed;

	// The derived constructors validate through this one so that the exception names their own parameter.
	private protected AppendStream(Stream inner, TAlgorithm algorithm, bool leaveOpen, [CallerArgumentExpression(nameof(algorithm))] string? algorithmParamName = null)
	{
		ArgumentNullException.ThrowIfNull(inner);
		ArgumentNullException.ThrowIfNull(algorithm, algorithmParamName);

		_inner = inner;
		_algorithm = algorithm;
		_leaveOpen = leaveOpen;
	}

	/// <summary>Gets the algorithm that receives the data.</summary>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	private protected TAlgorithm Algorithm
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);

			return _algorithm;
		}
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

	/// <summary>Resets the algorithm, discarding the data seen so far.</summary>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public void Reset()
	{
		Algorithm.Reset();
	}

	/// <inheritdoc />
	public override int Read(byte[] buffer, int offset, int count)
	{
		ValidateBufferArguments(buffer, offset, count);

		return Read(buffer.AsSpan(offset, count));
	}

	/// <inheritdoc />
	public sealed override int Read(Span<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		int read = _inner.Read(buffer);
		_algorithm.Append(buffer.Slice(0, read));
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
	public sealed override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		ValueTask<int> task = _inner.ReadAsync(buffer, cancellationToken);

		if (task.IsCompletedSuccessfully)
		{
			int read = task.Result;
			_algorithm.Append(buffer.Span.Slice(0, read));
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
	public sealed override void Write(ReadOnlySpan<byte> buffer)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_inner.Write(buffer);
		_algorithm.Append(buffer);
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
	public sealed override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		ValueTask task = _inner.WriteAsync(buffer, cancellationToken);

		if (task.IsCompletedSuccessfully)
		{
			task.GetAwaiter().GetResult();
			_algorithm.Append(buffer.Span);
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

	/// <summary>Disposes the algorithm and, unless <c>leaveOpen</c> was specified, the inner stream.</summary>
	/// <param name="disposing"><see langword="true" /> when called from <see cref="Stream.Dispose()" />.</param>
	protected override void Dispose(bool disposing)
	{
		if (disposing && !_disposed)
		{
			_disposed = true;
			_algorithm.Dispose();

			if (!_leaveOpen)
			{
				_inner.Dispose();
			}
		}

		base.Dispose(disposing);
	}

	/// <summary>Disposes the algorithm and, unless <c>leaveOpen</c> was specified, asynchronously disposes the inner stream.</summary>
	/// <returns>A task that represents the asynchronous dispose operation.</returns>
	public override ValueTask DisposeAsync()
	{
		if (_disposed)
		{
			return ValueTask.CompletedTask;
		}

		_disposed = true;
		_algorithm.Dispose();
		return _leaveOpen ? ValueTask.CompletedTask : _inner.DisposeAsync();
	}

	private async ValueTask<int> AwaitReadAsync(ValueTask<int> task, Memory<byte> buffer)
	{
		int read = await task.ConfigureAwait(false);
		_algorithm.Append(buffer.Span.Slice(0, read));
		return read;
	}

	private async ValueTask AwaitWriteAsync(ValueTask task, ReadOnlyMemory<byte> buffer)
	{
		await task.ConfigureAwait(false);
		_algorithm.Append(buffer.Span);
	}
}
