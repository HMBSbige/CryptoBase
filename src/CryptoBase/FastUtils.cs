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
		ref var data = ref MemoryMarshal.GetArrayDataReference(array);
		return ref Unsafe.Add(ref data, index);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Copy(byte* source, byte* destination, int count)
	{
		while (count >= 8)
		{
			*(ulong*)destination = *(ulong*)source;
			destination += 8;
			source += 8;
			count -= 8;
		}

		if (count >= 4)
		{
			*(uint*)destination = *(uint*)source;
			destination += 4;
			source += 4;
			count -= 4;
		}

		if (count >= 2)
		{
			*(ushort*)destination = *(ushort*)source;
			destination += 2;
			source += 2;
			count -= 2;
		}

		if (count >= 1)
		{
			*destination = *source;
		}
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		for (var i = 0; i < length; ++i)
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
		for (var i = 0; i < 16; ++i)
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
