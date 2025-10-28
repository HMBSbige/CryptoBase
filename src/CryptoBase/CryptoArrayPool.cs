namespace CryptoBase;

public sealed class CryptoArrayPool<T>(int length) : IDisposable where T : struct
{
	public readonly T[] Array = ArrayPool<T>.Shared.Rent(length);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Span<T> GetSpan()
	{
		return Array.AsSpan(0, length);
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(GetSpan()));
		ArrayPool<T>.Shared.Return(Array);
	}
}
