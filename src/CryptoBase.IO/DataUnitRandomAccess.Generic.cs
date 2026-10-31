using CryptoBase.IO.DataUnits;
using CryptoBase.IO.Storage;

namespace CryptoBase.IO;

/// <summary>
/// Provides positional data-unit encryption over a file handle.
/// </summary>
/// <typeparam name="TCipher">The data-unit cipher.</typeparam>
/// <remarks>
/// <para>
/// <typeparamref name="TCipher" /> must have a <see cref="IDataUnitCipher{TSelf}.TweakSize" /> of 16, such as <c>XtsMode&lt;AesCipher&gt;</c>. The tweak of each data unit is its data unit number as a 128-bit little-endian integer.
/// </para>
/// <para>
/// The file holds whole data units only. The data unit at byte offset <c>n * DataUnitSize</c> has data unit number <c>firstDataUnitNumber + n</c>.
/// </para>
/// <para>
/// Writes reach the file before they return. A write past the end pads its last data unit with zeros, and any gap between the old end and the write reads back as zeros. Writing part of an existing data unit reads that unit first, so the handle must also be readable. Reads never extend the file.
/// </para>
/// <para>
/// The instance owns the cipher and disposes it; <c>leaveOpen</c> controls only the handle.
/// Instances are not thread-safe. For parallel access, create one instance per thread over the same handle with <c>leaveOpen: true</c>, each with its own cipher.
/// </para>
/// </remarks>
public sealed class DataUnitRandomAccess<TCipher> : IDisposable where TCipher : class, IDataUnitCipher<TCipher>
{
	private readonly SafeFileHandle _handle;
	private readonly DataUnitTransform<TCipher> _transform;
	private readonly bool _leaveOpen;
	private bool _disposed;

	/// <summary>
	/// Initializes positional data-unit access over a file handle.
	/// </summary>
	/// <param name="handle">The file handle that stores the ciphertext.</param>
	/// <param name="cipher">The cipher; this instance takes ownership of it once the constructor succeeds.</param>
	/// <param name="dataUnitSize">The data unit size, in bytes; at least 16.</param>
	/// <param name="firstDataUnitNumber">The data unit number of the data unit at offset zero.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="handle" /> open on disposal.</param>
	/// <exception cref="ArgumentNullException"><paramref name="handle" /> or <paramref name="cipher" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><typeparamref name="TCipher" /> does not use a 16-byte tweak, or the file length is not a multiple of <paramref name="dataUnitSize" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="dataUnitSize" /> is less than 16.</exception>
	public DataUnitRandomAccess(SafeFileHandle handle, TCipher cipher, int dataUnitSize, UInt128 firstDataUnitNumber = default, bool leaveOpen = false)
	{
		ArgumentNullException.ThrowIfNull(handle);

		_handle = handle;
		_transform = new DataUnitTransform<TCipher>(new FileHandleStorage(handle), cipher, dataUnitSize, firstDataUnitNumber, nameof(handle));
		_leaveOpen = leaveOpen;
	}

	/// <summary>
	/// Gets the data unit size, in bytes.
	/// </summary>
	public int DataUnitSize => _transform.DataUnitSize;

	/// <summary>
	/// Gets the file length, in bytes.
	/// </summary>
	/// <returns>The file length.</returns>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public long GetLength()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _transform.GetLength();
	}

	/// <summary>
	/// Sets the file length; growth appends encrypted zero data units.
	/// </summary>
	/// <param name="length">The new length, in bytes; a multiple of <see cref="DataUnitSize" />.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="length" /> is negative.</exception>
	/// <exception cref="ArgumentException"><paramref name="length" /> is not a multiple of <see cref="DataUnitSize" />.</exception>
	/// <exception cref="InvalidDataException">The file ends inside a data unit.</exception>
	/// <exception cref="OverflowException">A data unit number would exceed <see cref="UInt128.MaxValue" />, or a data unit would end past <see cref="long.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public void SetLength(long length)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_transform.SetLength(length);
	}

	/// <summary>
	/// Reads and decrypts bytes starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The buffer that receives the plaintext.</param>
	/// <param name="offset">The file offset to read from.</param>
	/// <returns>The number of bytes read; fewer than requested only at the end of the file, and zero at or past it.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="InvalidDataException">The file ends inside a data unit.</exception>
	/// <exception cref="OverflowException">A data unit number would exceed <see cref="UInt128.MaxValue" />, or a data unit would end past <see cref="long.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public int Read(Span<byte> buffer, long offset)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _transform.Read(buffer, offset);
	}

	/// <summary>
	/// Encrypts and writes <paramref name="buffer" /> starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The plaintext to write; it is not modified.</param>
	/// <param name="offset">The file offset to write to.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="InvalidDataException">The file ends inside a data unit.</exception>
	/// <exception cref="OverflowException">A data unit number would exceed <see cref="UInt128.MaxValue" />, or a data unit would end past <see cref="long.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public void Write(ReadOnlySpan<byte> buffer, long offset)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_transform.Write(buffer, offset);
	}

	/// <summary>
	/// Asynchronously reads and decrypts bytes starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The buffer that receives the plaintext.</param>
	/// <param name="offset">The file offset to read from.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A value task whose result is the number of bytes read; fewer than requested only at the end of the file, and zero at or past it.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="InvalidDataException">The file ends inside a data unit.</exception>
	/// <exception cref="OverflowException">A data unit number would exceed <see cref="UInt128.MaxValue" />, or a data unit would end past <see cref="long.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _transform.ReadAsync(buffer, offset, cancellationToken);
	}

	/// <summary>
	/// Asynchronously encrypts and writes <paramref name="buffer" /> starting at <paramref name="offset" />.
	/// </summary>
	/// <param name="buffer">The plaintext to write; it is not modified.</param>
	/// <param name="offset">The file offset to write to.</param>
	/// <param name="cancellationToken">The token used to cancel the operation.</param>
	/// <returns>A value task that completes when the data is written.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="offset" /> is negative.</exception>
	/// <exception cref="InvalidDataException">The file ends inside a data unit.</exception>
	/// <exception cref="OverflowException">A data unit number would exceed <see cref="UInt128.MaxValue" />, or a data unit would end past <see cref="long.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _transform.WriteAsync(buffer, offset, cancellationToken);
	}

	/// <summary>
	/// Flushes the file data and metadata to disk.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance is disposed.</exception>
	public void Flush()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		RandomAccess.FlushToDisk(_handle);
	}

	/// <summary>
	/// Disposes the cipher and, unless <c>leaveOpen</c> was set, the file handle.
	/// </summary>
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_transform.Dispose();

		if (!_leaveOpen)
		{
			_handle.Dispose();
		}
	}
}
