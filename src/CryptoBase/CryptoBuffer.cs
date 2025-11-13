namespace CryptoBase;

public readonly ref struct CryptoBuffer<T> : IDisposable where T : struct
{
	private const int MaxBytesOnStack = 1024;

	private static int MinRentElements => MaxBytesOnStack / Unsafe.SizeOf<T>();

	private readonly T[]? _buffer;

	public Span<T> Span { get; }

	public CryptoBuffer(int length)
	{
		if (length < MinRentElements)
		{
			Span = new T[length];
		}
		else
		{
			_buffer = ArrayPool<T>.Shared.Rent(length);
			Span = _buffer.AsSpan(0, length);
		}
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
