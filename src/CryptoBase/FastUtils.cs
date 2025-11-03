namespace CryptoBase;

public static class FastUtils
{
	/// <inheritdoc cref="MemoryMarshal.GetReference{T}(Span{T})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetReference<T>(this Span<T> span)
	{
		return ref MemoryMarshal.GetReference(span);
	}

	/// <inheritdoc cref="MemoryMarshal.GetReference{T}(ReadOnlySpan{T})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetReference<T>(this ReadOnlySpan<T> span)
	{
		return ref MemoryMarshal.GetReference(span);
	}

	/// <inheritdoc cref="MemoryMarshal.GetArrayDataReference{T}" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ref T GetReference<T>(this T[] array)
	{
		return ref MemoryMarshal.GetArrayDataReference(array);
	}

	/// <inheritdoc cref="Vector256.Create{T}(Vector128{T})" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<T> BroadcastVector128ToVector256<T>(ref T source)
	{
		if (Avx2.IsSupported)
		{
			unsafe
			{
				return Avx2.BroadcastVector128ToVector256((byte*)Unsafe.AsPointer(ref source)).As<byte, T>();
			}
		}

		ref Vector128<T> v = ref Unsafe.As<T, Vector128<T>>(ref source);
		return Vector256.Create(v);
	}

	/// <inheritdoc cref="Avx512F.BroadcastVector128ToVector512(uint*)" />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<T> BroadcastVector128ToVector512<T>(ref T source)
	{
		if (Avx512F.IsSupported)
		{
			unsafe
			{
				return Avx512F.BroadcastVector128ToVector512((uint*)Unsafe.AsPointer(ref source)).As<uint, T>();
			}
		}

		Vector256<T> v256 = BroadcastVector128ToVector256(ref source);
		return Vector512.Create(v256);
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	public static void Xor(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int i = 0;
		int left = length;

		ref byte streamRef = ref stream.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		if (Vector512.IsHardwareAccelerated)
		{
			while (left >= Vector512<byte>.Count)
			{
				ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref streamRef, i));
				ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector512<byte> dst = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref destinationRef, i));

				dst = v0 ^ v1;
				i += Vector512<byte>.Count;
				left -= Vector512<byte>.Count;
			}
		}

		if (Vector256.IsHardwareAccelerated)
		{
			while (left >= Vector256<byte>.Count)
			{
				ref Vector256<byte> v0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref streamRef, i));
				ref Vector256<byte> v1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector256<byte> dst = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref destinationRef, i));

				dst = v0 ^ v1;
				i += Vector256<byte>.Count;
				left -= Vector256<byte>.Count;
			}
		}

		if (Vector128.IsHardwareAccelerated)
		{
			while (left >= Vector128<byte>.Count)
			{
				ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref streamRef, i));
				ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector128<byte> dst = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref destinationRef, i));

				dst = v0 ^ v1;
				i += Vector128<byte>.Count;
				left -= Vector128<byte>.Count;
			}
		}

		while (left >= sizeof(ulong))
		{
			ref ulong v0 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref streamRef, i));
			ref ulong v1 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref sourceRef, i));
			ref ulong dst = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref destinationRef, i));

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref uint v0 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref streamRef, i));
			ref uint v1 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, i));
			ref uint dst = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref destinationRef, i));

			dst = v0 ^ v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			Unsafe.Add(ref destinationRef, i) = (byte)(Unsafe.Add(ref sourceRef, i) ^ Unsafe.Add(ref streamRef, i));
		}
	}

	/// <summary>
	/// source ^= stream
	/// </summary>
	public static void Xor(Span<byte> source, ReadOnlySpan<byte> stream, int length)
	{
		int i = 0;
		int left = length;

		ref byte streamRef = ref stream.GetReference();
		ref byte sourceRef = ref source.GetReference();

		if (Vector512.IsHardwareAccelerated)
		{
			while (left >= Vector512<byte>.Count)
			{
				ref Vector512<byte> v0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector512<byte> v1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref streamRef, i));

				v0 ^= v1;
				i += Vector512<byte>.Count;
				left -= Vector512<byte>.Count;
			}
		}

		if (Vector256.IsHardwareAccelerated)
		{
			while (left >= Vector256<byte>.Count)
			{
				ref Vector256<byte> v0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector256<byte> v1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref streamRef, i));

				v0 ^= v1;
				i += Vector256<byte>.Count;
				left -= Vector256<byte>.Count;
			}
		}

		if (Vector128.IsHardwareAccelerated)
		{
			while (left >= Vector128<byte>.Count)
			{
				ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, i));
				ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref streamRef, i));

				v0 ^= v1;
				i += Vector128<byte>.Count;
				left -= Vector128<byte>.Count;
			}
		}

		while (left >= sizeof(ulong))
		{
			ref ulong v0 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref sourceRef, i));
			ref ulong v1 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref streamRef, i));

			v0 ^= v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref uint v0 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, i));
			ref uint v1 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref streamRef, i));

			v0 ^= v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			Unsafe.Add(ref sourceRef, i) ^= Unsafe.Add(ref streamRef, i);
		}
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Xor16(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (Vector128.IsHardwareAccelerated)
		{
			ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref stream.GetReference());
			ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref source.GetReference());
			ref Vector128<byte> dst = ref Unsafe.As<byte, Vector128<byte>>(ref destination.GetReference());

			dst = v0 ^ v1;
		}
		else
		{
			ref UInt128 v0 = ref Unsafe.As<byte, UInt128>(ref stream.GetReference());
			ref UInt128 v1 = ref Unsafe.As<byte, UInt128>(ref source.GetReference());
			ref UInt128 dst = ref Unsafe.As<byte, UInt128>(ref destination.GetReference());

			dst = v0 ^ v1;
		}
	}

	/// <summary>
	/// source ^= stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Xor16(Span<byte> source, ReadOnlySpan<byte> stream)
	{
		if (Vector128.IsHardwareAccelerated)
		{
			ref Vector128<byte> v0 = ref Unsafe.As<byte, Vector128<byte>>(ref source.GetReference());
			ref Vector128<byte> v1 = ref Unsafe.As<byte, Vector128<byte>>(ref stream.GetReference());

			v0 ^= v1;
		}
		else
		{
			ref UInt128 v0 = ref Unsafe.As<byte, UInt128>(ref source.GetReference());
			ref UInt128 v1 = ref Unsafe.As<byte, UInt128>(ref stream.GetReference());

			v0 ^= v1;
		}
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void XorLess16(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int i = 0;
		int left = length;

		ref byte streamRef = ref stream.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		if (left >= sizeof(ulong))
		{
			ref ulong v0 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref streamRef, i));
			ref ulong v1 = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref sourceRef, i));
			ref ulong dst = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref destinationRef, i));

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref uint v0 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref streamRef, i));
			ref uint v1 = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref sourceRef, i));
			ref uint dst = ref Unsafe.As<byte, uint>(ref Unsafe.Add(ref destinationRef, i));

			dst = v0 ^ v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			Unsafe.Add(ref destinationRef, i) = (byte)(Unsafe.Add(ref sourceRef, i) ^ Unsafe.Add(ref streamRef, i));
		}
	}
}
