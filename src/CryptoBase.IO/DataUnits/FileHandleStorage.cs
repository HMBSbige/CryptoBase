namespace CryptoBase.IO.DataUnits;

/// <summary>
/// Adapts a file handle to <see cref="IPositionalStorage" /> through <see cref="RandomAccess" />.
/// </summary>
internal sealed class FileHandleStorage(SafeFileHandle handle) : IPositionalStorage
{
	public long GetLength()
	{
		return RandomAccess.GetLength(handle);
	}

	public void SetLength(long length)
	{
		RandomAccess.SetLength(handle, length);
	}

	public int Read(Span<byte> buffer, long offset)
	{
		return RandomAccess.Read(handle, buffer, offset);
	}

	public void Write(ReadOnlySpan<byte> buffer, long offset)
	{
		RandomAccess.Write(handle, buffer, offset);
	}

	public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		return RandomAccess.ReadAsync(handle, buffer, offset, cancellationToken);
	}

	public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		return RandomAccess.WriteAsync(handle, buffer, offset, cancellationToken);
	}
}
