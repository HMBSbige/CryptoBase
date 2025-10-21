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
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	public static void Xor(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int i = 0;
		int left = length;

		if (Vector512.IsHardwareAccelerated)
		{
			while (left >= Vector512<byte>.Count)
			{
				ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref stream.GetRef(i));
				ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref source.GetRef(i));
				ref Vector512<byte> dst = ref Unsafe.As<byte, Vector512<byte>>(ref destination.GetRef(i));

				dst = v0 ^ v1;
				i += Vector512<byte>.Count;
				left -= Vector512<byte>.Count;
			}
		}

		if (Vector256.IsHardwareAccelerated)
		{
			while (left >= Vector256<byte>.Count)
			{
				ref Vector256<byte> v0 = ref Unsafe.As<byte, Vector256<byte>>(ref stream.GetRef(i));
				ref Vector256<byte> v1 = ref Unsafe.As<byte, Vector256<byte>>(ref source.GetRef(i));
				ref Vector256<byte> dst = ref Unsafe.As<byte, Vector256<byte>>(ref destination.GetRef(i));

				dst = v0 ^ v1;
				i += Vector256<byte>.Count;
				left -= Vector256<byte>.Count;
			}
		}

		if (Vector128.IsHardwareAccelerated)
		{
			while (left >= Vector128<byte>.Count)
			{
				ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref stream.GetRef(i));
				ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref source.GetRef(i));
				ref Vector128<byte> dst = ref Unsafe.As<byte, Vector128<byte>>(ref destination.GetRef(i));

				dst = v0 ^ v1;
				i += Vector128<byte>.Count;
				left -= Vector128<byte>.Count;
			}
		}

		while (left >= sizeof(ulong))
		{
			ref ulong v0 = ref Unsafe.As<byte, ulong>(ref stream.GetRef(i));
			ref ulong v1 = ref Unsafe.As<byte, ulong>(ref source.GetRef(i));
			ref ulong dst = ref Unsafe.As<byte, ulong>(ref destination.GetRef(i));

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref uint v0 = ref Unsafe.As<byte, uint>(ref stream.GetRef(i));
			ref uint v1 = ref Unsafe.As<byte, uint>(ref source.GetRef(i));
			ref uint dst = ref Unsafe.As<byte, uint>(ref destination.GetRef(i));

			dst = v0 ^ v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			destination.GetRef(i) = (byte)(source.GetRef(i) ^ stream.GetRef(i));
		}
	}
}
