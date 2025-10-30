namespace CryptoBase;

public sealed class CryptoArrayPool<T>(int length) : IDisposable where T : struct
{
	public readonly T[] Array = ArrayPool<T>.Shared.Rent(length);

	public Span<T> Span
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Array.AsSpan(0, length);
	}

	public ref T this[int index]
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => ref Array[index];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public ref T GetReference()
	{
		return ref Array.GetReference();
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Span));
		ArrayPool<T>.Shared.Return(Array);
	}
}
