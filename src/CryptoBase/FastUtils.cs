namespace CryptoBase;

public static class FastUtils
{
	/// <summary>
	/// Get span ref without bounds checking
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetRef<T>(this Span<T> span, int index)
	{
		return ref Unsafe.Add(ref MemoryMarshal.GetReference(span), index);
	}

	/// <summary>
	/// Get array ref without bounds checking
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetRef<T>(this T[] array, int index)
	{
		ref T data = ref MemoryMarshal.GetArrayDataReference(array);
		return ref Unsafe.Add(ref data, index);
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		for (int i = 0; i < length; ++i)
		{
			*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
		}
	}

	/// <summary>
	/// destination[..16] = source[..16] ^ stream[..16]
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Xor16(byte* stream, byte* source, byte* destination)
	{
		for (int i = 0; i < 16; ++i)
		{
			*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
			++i;
			*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
			++i;
			*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
			++i;
			*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
		}
	}
}
