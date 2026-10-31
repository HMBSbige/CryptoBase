namespace CryptoBase.IO.Storage;

/// <summary>
/// Provides positional access to a ciphertext backend, such as a file handle or a seekable stream.
/// </summary>
/// <remarks>
/// Reads may return fewer bytes than requested; <see cref="PositionalStorageExtensions.TryReadExactly" /> loops until the request is satisfied or the backend ends.
/// </remarks>
internal interface IPositionalStorage
{
	/// <summary>
	/// Gets the backend length, in bytes.
	/// </summary>
	long GetLength();

	/// <summary>
	/// Sets the backend length, in bytes.
	/// </summary>
	void SetLength(long length);

	/// <summary>
	/// Reads bytes starting at <paramref name="offset" /> and returns the number of bytes read.
	/// </summary>
	int Read(Span<byte> buffer, long offset);

	/// <summary>
	/// Writes all of <paramref name="buffer" /> starting at <paramref name="offset" />.
	/// </summary>
	void Write(ReadOnlySpan<byte> buffer, long offset);

	/// <summary>
	/// Asynchronously reads bytes starting at <paramref name="offset" /> and returns the number of bytes read.
	/// </summary>
	ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken);

	/// <summary>
	/// Asynchronously writes all of <paramref name="buffer" /> starting at <paramref name="offset" />.
	/// </summary>
	ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken);
}
