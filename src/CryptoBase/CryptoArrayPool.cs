namespace CryptoBase;

public sealed class CryptoArrayPool<T>(int length) : IDisposable where T : struct
{
	private readonly T[] _array = ArrayPool<T>.Shared.Rent(length);

	public Span<T> Span
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => _array.AsSpan(0, length);
	}

	public ref T this[int index]
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => ref _array[index];
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public ref T GetReference()
	{
		return ref _array.GetReference();
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Span));
		ArrayPool<T>.Shared.Return(_array);
	}
}
