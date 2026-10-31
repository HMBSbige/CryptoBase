using CryptoBase.IO.DataUnits;
using CryptoBase.IO.Storage;

namespace CryptoBase.IO;

/// <summary>
/// Provides data-unit encryption over a seekable stream.
/// </summary>
/// <typeparam name="TCipher">The data-unit cipher.</typeparam>
/// <remarks>
/// <para>
/// <typeparamref name="TCipher" /> must have a <see cref="IDataUnitCipher{TSelf}.TweakSize" /> of 16, such as <c>XtsMode&lt;AesCipher&gt;</c>. The tweak of each data unit is its data unit number as a 128-bit little-endian integer.
/// </para>
/// <para>
/// The inner stream holds whole data units only. The data unit at byte offset <c>n * DataUnitSize</c> has data unit number <c>firstDataUnitNumber + n</c>. The stream position is the inner stream offset and starts at zero; the stream seeks the inner stream before each access, so the inner stream position is not preserved.
/// </para>
/// <para>
/// A write past the end pads its last data unit with zeros, and any gap between the old end and the write reads back as zeros. Writing part of an existing data unit reads that unit first, so the inner stream must also be readable. Reads never extend the inner stream.
/// </para>
/// <para>
/// Writes of whole aligned data units reach the inner stream before they return. A partial write stays in the stream until a read or write touches another data unit or the stream is flushed or disposed; call <see cref="Flush" /> before using the inner stream directly. Do not change the inner stream elsewhere while the stream uses it.
/// </para>
/// <para>
/// The instance owns the cipher and disposes it; <c>leaveOpen</c> controls only the inner stream.
/// Instances are not thread-safe.
/// </para>
/// </remarks>
public sealed class DataUnitStream<TCipher> : Stream where TCipher : class, IDataUnitCipher<TCipher>
{
	private readonly Stream _inner;
	private readonly DataUnitTransform<TCipher> _transform;
	private readonly bool _leaveOpen;
	private readonly byte[] _unit;
	// The ciphertext of _unit as it is written, kept apart so that a failed write leaves the plaintext cached.
	private byte[]? _ciphertext;
	private long? _unitStart;
	private bool _unitDirty;
	private long _position;
	private bool _disposed;

	/// <summary>
	/// Initializes a data-unit stream over a seekable stream.
	/// </summary>
	/// <param name="inner">The seekable stream that stores the ciphertext.</param>
	/// <param name="cipher">The cipher; this instance takes ownership of it once the constructor succeeds.</param>
	/// <param name="dataUnitSize">The data unit size, in bytes; at least 16.</param>
	/// <param name="firstDataUnitNumber">The data unit number of the data unit at offset zero.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="cipher" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not seekable or its length is not a multiple of <paramref name="dataUnitSize" />, or <typeparamref name="TCipher" /> does not use a 16-byte tweak.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="dataUnitSize" /> is less than 16.</exception>
	public DataUnitStream(Stream inner, TCipher cipher, int dataUnitSize, UInt128 firstDataUnitNumber = default, bool leaveOpen = false)
	{
		ArgumentNullException.ThrowIfNull(inner);

		if (!inner.CanSeek)
		{
			throw new ArgumentException("The stream must support seeking.", nameof(inner));
		}

		_inner = inner;
		_transform = new DataUnitTransform<TCipher>(new SeekableStreamStorage(inner), cipher, dataUnitSize, firstDataUnitNumber, nameof(inner));
		_leaveOpen = leaveOpen;
		_unit = GC.AllocateUninitializedArray<byte>(dataUnitSize);
	}

	/// <summary>
	/// Gets the data unit size, in bytes.
	/// </summary>
	public int DataUnitSize => _transform.DataUnitSize;

	/// <inheritdoc />
	public override bool CanRead => !_disposed && _inner.CanRead;

	/// <inheritdoc />
	public override bool CanWrite => !_disposed && _inner.CanWrite;

	/// <inheritdoc />
	public override bool CanSeek => !_disposed;

	/// <inheritdoc />
	/// <remarks>The length includes a changed data unit that has not reached the inner stream yet.</remarks>
	public override long Length
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return GetLength();
		}
	}

	/// <inheritdoc />
	/// <remarks>The position may exceed <see cref="Length" />; reading there returns zero bytes and writing there extends the stream.</remarks>
	public override long Position
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _position;
		}
		set
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			ArgumentOutOfRangeException.ThrowIfNegative(value);
			_position = value;
		}
	}

	/// <inheritdoc />
	public override long Seek(long offset, SeekOrigin origin)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		long position = origin switch
		{
			SeekOrigin.Begin => offset,
			SeekOrigin.Current => _position + offset,
			SeekOrigin.End => GetLength() + offset,
			_ => throw new ArgumentException("Invalid seek origin.", nameof(origin))
		};

		if (position < 0)
		{
			throw new IOException("An attempt was made to move the position before the beginning of the stream.");
		}

		_position = position;
		return position;
	}

	/// <inheritdoc />
	/// <remarks>
	/// <paramref name="value" /> must be a multiple of <see cref="DataUnitSize" />. Growth appends encrypted zero data units. If the position is beyond the new length, it moves to the new end.
	/// </remarks>
	public override void SetLength(long value)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_transform.SetLength(value);

		if (_unitStart >= value)
		{
			DropUnit();
		}

		_position = Math.Min(_position, value);
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
		ThrowIfNotReadable();
		long position = _position;

		while (!buffer.IsEmpty)
		{
			int read = ReadFromUnit(buffer, position);

			if (read is 0)
			{
				if (TryGetWholeUnits(buffer.Length, position, out int units))
				{
					FlushUnit();
					read = _transform.Read(buffer.Slice(0, units), position);
				}
				else if (LoadUnit(position, create: false))
				{
					read = ReadFromUnit(buffer, position);
				}

				if (read is 0)
				{
					break;
				}
			}

			buffer = buffer.Slice(read);
			position += read;
		}

		return Advance(position);
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
	public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfNotReadable();

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled<int>(cancellationToken);
		}

		int read = ReadFromUnit(buffer.Span, _position);

		if (read == buffer.Length)
		{
			_position += read;
			return ValueTask.FromResult(read);
		}

		return ReadCoreAsync(buffer.Slice(read), _position + read, cancellationToken);
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
		ThrowIfNotWritable();

		if (buffer.IsEmpty)
		{
			return;
		}

		_transform.ValidateRange(_position, buffer.Length);
		long position = _position;

		while (!buffer.IsEmpty)
		{
			int written = WriteToUnit(buffer, position);

			if (written is 0)
			{
				if (TryGetWholeUnits(buffer.Length, position, out int units))
				{
					// Write a cached unit outside the range first, so the transform does not fill it as a gap.
					DropUnitWithin(position, units);
					FlushUnit();
					_transform.Write(buffer.Slice(0, units), position);
					written = units;
				}
				else
				{
					LoadUnit(position, create: true);
					written = WriteToUnit(buffer, position);
				}
			}

			buffer = buffer.Slice(written);
			position += written;
		}

		_position = position;
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
	public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowIfNotWritable();

		if (cancellationToken.IsCancellationRequested)
		{
			return ValueTask.FromCanceled(cancellationToken);
		}

		if (buffer.IsEmpty)
		{
			return ValueTask.CompletedTask;
		}

		_transform.ValidateRange(_position, buffer.Length);
		int written = WriteToUnit(buffer.Span, _position);

		if (written == buffer.Length)
		{
			_position += written;
			return ValueTask.CompletedTask;
		}

		return WriteCoreAsync(buffer.Slice(written), _position + written, cancellationToken);
	}

	/// <inheritdoc />
	/// <remarks>Writes a changed data unit to the inner stream, then flushes the inner stream.</remarks>
	public override void Flush()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		FlushUnit();
		_inner.Flush();
	}

	/// <inheritdoc />
	/// <remarks>Writes a changed data unit to the inner stream, then flushes the inner stream.</remarks>
	public override Task FlushAsync(CancellationToken cancellationToken)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (cancellationToken.IsCancellationRequested)
		{
			return Task.FromCanceled(cancellationToken);
		}

		return _unitDirty ? FlushCoreAsync(cancellationToken) : _inner.FlushAsync(cancellationToken);
	}

	/// <inheritdoc />
	/// <remarks>Writes a changed data unit to the inner stream before releasing the cipher and, unless <c>leaveOpen</c> was set, the inner stream.</remarks>
	public override async ValueTask DisposeAsync()
	{
		if (_disposed)
		{
			return;
		}

		try
		{
			await FlushUnitAsync(CancellationToken.None).ConfigureAwait(false);
		}
		finally
		{
			Release();

			if (!_leaveOpen)
			{
				await _inner.DisposeAsync().ConfigureAwait(false);
			}
		}
	}

	/// <inheritdoc />
	/// <remarks>Writes a changed data unit to the inner stream before releasing the cipher and, unless <c>leaveOpen</c> was set, the inner stream.</remarks>
	protected override void Dispose(bool disposing)
	{
		if (disposing && !_disposed)
		{
			try
			{
				FlushUnit();
			}
			finally
			{
				Release();

				if (!_leaveOpen)
				{
					_inner.Dispose();
				}
			}
		}

		base.Dispose(disposing);
	}

	private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, long position, CancellationToken cancellationToken)
	{
		while (!buffer.IsEmpty)
		{
			int read = ReadFromUnit(buffer.Span, position);

			if (read is 0)
			{
				if (TryGetWholeUnits(buffer.Length, position, out int units))
				{
					await FlushUnitAsync(cancellationToken).ConfigureAwait(false);
					read = await _transform.ReadAsync(buffer.Slice(0, units), position, cancellationToken).ConfigureAwait(false);
				}
				else if (await LoadUnitAsync(position, create: false, cancellationToken).ConfigureAwait(false))
				{
					read = ReadFromUnit(buffer.Span, position);
				}

				if (read is 0)
				{
					break;
				}
			}

			buffer = buffer.Slice(read);
			position += read;
		}

		return Advance(position);
	}

	private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> buffer, long position, CancellationToken cancellationToken)
	{
		while (!buffer.IsEmpty)
		{
			int written = WriteToUnit(buffer.Span, position);

			if (written is 0)
			{
				if (TryGetWholeUnits(buffer.Length, position, out int units))
				{
					DropUnitWithin(position, units);
					await FlushUnitAsync(cancellationToken).ConfigureAwait(false);
					await _transform.WriteAsync(buffer.Slice(0, units), position, cancellationToken).ConfigureAwait(false);
					written = units;
				}
				else
				{
					await LoadUnitAsync(position, create: true, cancellationToken).ConfigureAwait(false);
					written = WriteToUnit(buffer.Span, position);
				}
			}

			buffer = buffer.Slice(written);
			position += written;
		}

		_position = position;
	}

	private async Task FlushCoreAsync(CancellationToken cancellationToken)
	{
		await FlushUnitAsync(cancellationToken).ConfigureAwait(false);
		await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
	}

	private long? DirtyUnitStart => _unitDirty ? _unitStart : null;

	private long GetLength()
	{
		long length = _transform.GetLength();
		return DirtyUnitStart is { } unitStart ? Math.Max(length, unitStart + DataUnitSize) : length;
	}

	/// <summary>
	/// Moves the position to <paramref name="position" /> and returns how far it moved.
	/// </summary>
	private int Advance(long position)
	{
		int moved = (int)(position - _position);
		_position = position;
		return moved;
	}

	private bool TryGetWholeUnits(int length, long position, out int units)
	{
		units = length - length % DataUnitSize;
		return units > 0 && position % DataUnitSize is 0;
	}

	/// <summary>
	/// Gets at most <paramref name="length" /> bytes of cached plaintext from <paramref name="position" /> to the end of its data unit, or an empty span when that data unit is not cached.
	/// </summary>
	private Span<byte> GetCachedRange(long position, int length)
	{
		if (_unitStart is { } unitStart && (ulong)(position - unitStart) < (ulong)_unit.Length)
		{
			int unitOffset = (int)(position - unitStart);
			return _unit.AsSpan(unitOffset, Math.Min(_unit.Length - unitOffset, length));
		}

		return default;
	}

	/// <summary>
	/// Copies cached plaintext at <paramref name="position" /> into <paramref name="buffer" /> and returns the bytes copied, or zero when the data unit at <paramref name="position" /> is not cached.
	/// </summary>
	private int ReadFromUnit(Span<byte> buffer, long position)
	{
		Span<byte> cached = GetCachedRange(position, buffer.Length);
		cached.CopyTo(buffer);
		return cached.Length;
	}

	/// <summary>
	/// Copies <paramref name="buffer" /> into the cached plaintext at <paramref name="position" /> and returns the bytes copied, or zero when the data unit at <paramref name="position" /> is not cached.
	/// </summary>
	private int WriteToUnit(ReadOnlySpan<byte> buffer, long position)
	{
		Span<byte> cached = GetCachedRange(position, buffer.Length);

		if (cached.IsEmpty)
		{
			return 0;
		}

		buffer.Slice(0, cached.Length).CopyTo(cached);
		_unitDirty = true;
		return cached.Length;
	}

	/// <summary>
	/// Caches the data unit that contains <paramref name="position" />. When it does not exist, returns <see langword="false" />, or starts it from zeros if <paramref name="create" /> is set.
	/// </summary>
	private bool LoadUnit(long position, bool create)
	{
		FlushUnit();
		long unitStart = position - position % DataUnitSize;
		_unitStart = null;

		if (_transform.Read(_unit, unitStart) is 0)
		{
			if (!create)
			{
				return false;
			}

			Array.Clear(_unit);
		}

		_unitStart = unitStart;
		return true;
	}

	private async ValueTask<bool> LoadUnitAsync(long position, bool create, CancellationToken cancellationToken)
	{
		await FlushUnitAsync(cancellationToken).ConfigureAwait(false);
		long unitStart = position - position % DataUnitSize;
		_unitStart = null;

		if (await _transform.ReadAsync(_unit, unitStart, cancellationToken).ConfigureAwait(false) is 0)
		{
			if (!create)
			{
				return false;
			}

			Array.Clear(_unit);
		}

		_unitStart = unitStart;
		return true;
	}

	private void FlushUnit()
	{
		if (DirtyUnitStart is { } unitStart)
		{
			_transform.WriteUnit(_unit, _ciphertext ??= GC.AllocateUninitializedArray<byte>(DataUnitSize), unitStart);
			_unitDirty = false;
		}
	}

	private async ValueTask FlushUnitAsync(CancellationToken cancellationToken)
	{
		if (DirtyUnitStart is { } unitStart)
		{
			await _transform.WriteUnitAsync(_unit, _ciphertext ??= GC.AllocateUninitializedArray<byte>(DataUnitSize), unitStart, cancellationToken).ConfigureAwait(false);
			_unitDirty = false;
		}
	}

	/// <summary>
	/// Discards the cached data unit when a write of whole units at <paramref name="position" /> replaces it.
	/// </summary>
	private void DropUnitWithin(long position, int length)
	{
		if (_unitStart >= position && _unitStart < position + length)
		{
			DropUnit();
		}
	}

	private void DropUnit()
	{
		_unitStart = null;
		_unitDirty = false;
		CryptographicOperations.ZeroMemory(_unit);
	}

	private void Release()
	{
		_disposed = true;
		DropUnit();
		_transform.Dispose();
	}

	private void ThrowIfNotReadable()
	{
		if (!_inner.CanRead)
		{
			throw new NotSupportedException("The stream does not support reading.");
		}
	}

	private void ThrowIfNotWritable()
	{
		if (!_inner.CanWrite)
		{
			throw new NotSupportedException("The stream does not support writing.");
		}
	}
}
