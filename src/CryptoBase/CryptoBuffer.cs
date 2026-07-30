namespace CryptoBase;

/// <summary>
/// Provides temporary storage that is cleared when disposed.
/// </summary>
public readonly ref struct CryptoBuffer<T> : IDisposable where T : struct
{
	private const int MaxSmallArrayBytes = 256;

	private static int MaxSmallArrayElements => MaxSmallArrayBytes / Unsafe.SizeOf<T>();

	private readonly T[]? _buffer;

	/// <summary>
	/// Gets the usable buffer.
	/// </summary>
	public Span<T> Span { get; }

	/// <summary>
	/// Creates a buffer with the specified length.
	/// </summary>
	public CryptoBuffer(int length)
	{
		if (length <= MaxSmallArrayElements)
		{
			Span = new T[length];
		}
		else
		{
			_buffer = ArrayPool<T>.Shared.Rent(length);
			Span = _buffer.AsSpan(0, length);
		}
	}

	/// <summary>
	/// Wraps an existing buffer.
	/// </summary>
	public CryptoBuffer(Span<T> buffer)
	{
		Span = buffer;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Span));

		if (_buffer is not null)
		{
			ArrayPool<T>.Shared.Return(_buffer);
		}
	}
}
