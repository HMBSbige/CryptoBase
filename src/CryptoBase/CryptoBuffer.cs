namespace CryptoBase;

public readonly ref struct CryptoBuffer<T> : IDisposable where T : struct
{
	private readonly T[]? _buffer;

	public Span<T> Span { get; }

	public CryptoBuffer(int length)
	{
		_buffer = ArrayPool<T>.Shared.Rent(length);
		Span = _buffer.AsSpan(0, length);
	}

	public CryptoBuffer(Span<T> buffer)
	{
		Span = buffer;
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Span));

		if (_buffer is not null)
		{
			ArrayPool<T>.Shared.Return(_buffer);
		}
	}
}
