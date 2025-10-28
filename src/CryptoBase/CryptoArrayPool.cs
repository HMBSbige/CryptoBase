namespace CryptoBase;

public sealed class CryptoArrayPool<T>(int length) : IDisposable where T : struct
{
	public readonly T[] Array = ArrayPool<T>.Shared.Rent(length);

	public Span<T> Span
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Array.AsSpan(0, length);
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Span));
		ArrayPool<T>.Shared.Return(Array);
	}
}
