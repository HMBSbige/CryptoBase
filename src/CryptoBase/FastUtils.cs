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
	public static void Xor(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int i = 0;
		int left = length;

		while (left >= 64)
		{
			Vector512<byte> va = CreateVector512Unsafe(stream.Slice(i));
			Vector512<byte> vb = CreateVector512Unsafe(source.Slice(i));
			(va ^ vb).CopyTo(destination.Slice(i));

			i += 64;
			left -= 64;
		}

		if (left >= 32)
		{
			Vector256<byte> va = CreateVector256Unsafe(stream.Slice(i));
			Vector256<byte> vb = CreateVector256Unsafe(source.Slice(i));
			(va ^ vb).CopyTo(destination.Slice(i));

			i += 32;
			left -= 32;
		}

		if (left >= 16)
		{
			Vector128<byte> va = CreateVector128Unsafe(stream.Slice(i));
			Vector128<byte> vb = CreateVector128Unsafe(source.Slice(i));
			(va ^ vb).CopyTo(destination.Slice(i));

			i += 16;
		}

		for (; i < length; ++i)
		{
			destination.GetRef(i) = (byte)(source.GetRef(i) ^ stream.GetRef(i));
		}
	}

	/// <summary>
	/// destination = source ^ stream
	/// TODO: Remove
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
