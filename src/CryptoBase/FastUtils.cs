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
	/// Get span ref without bounds checking
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetRef<T>(this ReadOnlySpan<T> span, int index)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<T> CreateVector128Unsafe<T>(ReadOnlySpan<T> values)
	{
		return Unsafe.ReadUnaligned<Vector128<T>>(ref Unsafe.As<T, byte>(ref MemoryMarshal.GetReference(values)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> CreateVector256Unsafe<T>(ReadOnlySpan<T> values)
	{
		return Unsafe.ReadUnaligned<Vector256<T>>(ref Unsafe.As<T, byte>(ref MemoryMarshal.GetReference(values)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> CreateVector512Unsafe<T>(ReadOnlySpan<T> values)
	{
		return Unsafe.ReadUnaligned<Vector512<T>>(ref Unsafe.As<T, byte>(ref MemoryMarshal.GetReference(values)));
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
}
