namespace CryptoBase;

public readonly ref struct CryptoBuffer : IDisposable
{
	private readonly byte[]? _buffer;

	public Span<byte> Span { get; }

	public CryptoBuffer(int length)
	{
		_buffer = ArrayPool<byte>.Shared.Rent(length);
		Span = _buffer.AsSpan(0, length);
	}

	public CryptoBuffer(Span<byte> buffer)
	{
		Span = buffer;
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(Span);

		if (_buffer is not null)
		{
			ArrayPool<byte>.Shared.Return(_buffer);
		}
	}
}
