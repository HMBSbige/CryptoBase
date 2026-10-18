namespace CryptoBase.IO.DataUnits;

/// <summary>
/// Adapts a seekable stream to <see cref="IPositionalStorage" /> by positioning it before each operation.
/// </summary>
internal sealed class SeekableStreamStorage(Stream stream) : IPositionalStorage
{
	public long GetLength()
	{
		return stream.Length;
	}

	public void SetLength(long length)
	{
		stream.SetLength(length);
	}

	public int Read(Span<byte> buffer, long offset)
	{
		stream.Position = offset;
		return stream.Read(buffer);
	}

	public void Write(ReadOnlySpan<byte> buffer, long offset)
	{
		stream.Position = offset;
		stream.Write(buffer);
	}

	public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		stream.Position = offset;
		return stream.ReadAsync(buffer, cancellationToken);
	}

	public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		stream.Position = offset;
		return stream.WriteAsync(buffer, cancellationToken);
	}
}
