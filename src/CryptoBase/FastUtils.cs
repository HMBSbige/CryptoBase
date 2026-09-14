namespace CryptoBase;

/// <summary>
/// Provides low-level helpers optimized for cryptographic operations.
/// </summary>
public static class FastUtils
{
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

		if (Vector512.IsHardwareAccelerated && left >= 4096)
		{
			int batchSize = Vector512<byte>.Count * 8;

			while (left >= batchSize)
			{
				nuint offset = (nuint)i;
				Vector512<byte> vector0 = Vector512.LoadUnsafe(ref streamRef, offset) ^ Vector512.LoadUnsafe(ref sourceRef, offset);
				Vector512<byte> vector1 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)Vector512<byte>.Count) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)Vector512<byte>.Count);
				Vector512<byte> vector2 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 2)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 2));
				Vector512<byte> vector3 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 3)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 3));

				vector0.StoreUnsafe(ref destinationRef, offset);
				vector1.StoreUnsafe(ref destinationRef, offset + (nuint)Vector512<byte>.Count);
				vector2.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 2));
				vector3.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 3));

				vector0 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 4)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 4));
				vector1 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 5)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 5));
				vector2 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 6)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 6));
				vector3 = Vector512.LoadUnsafe(ref streamRef, offset + (nuint)(Vector512<byte>.Count * 7)) ^ Vector512.LoadUnsafe(ref sourceRef, offset + (nuint)(Vector512<byte>.Count * 7));

				vector0.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 4));
				vector1.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 5));
				vector2.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 6));
				vector3.StoreUnsafe(ref destinationRef, offset + (nuint)(Vector512<byte>.Count * 7));

				i += batchSize;
				left -= batchSize;
			}
		}

		if (Vector512.IsHardwareAccelerated)
		{
			while (left >= Vector512<byte>.Count)
			{
				nuint offset = (nuint)i;
				(Vector512.LoadUnsafe(ref streamRef, offset) ^ Vector512.LoadUnsafe(ref sourceRef, offset)).StoreUnsafe(ref destinationRef, offset);
				i += Vector512<byte>.Count;
				left -= Vector512<byte>.Count;
			}
		}

		if (Vector256.IsHardwareAccelerated)
		{
			while (left >= Vector256<byte>.Count)
			{
				nuint offset = (nuint)i;
				(Vector256.LoadUnsafe(ref streamRef, offset) ^ Vector256.LoadUnsafe(ref sourceRef, offset)).StoreUnsafe(ref destinationRef, offset);
				i += Vector256<byte>.Count;
				left -= Vector256<byte>.Count;
			}
		}

		if (Vector128.IsHardwareAccelerated)
		{
			while (left >= Vector128<byte>.Count)
			{
				nuint offset = (nuint)i;
				(Vector128.LoadUnsafe(ref streamRef, offset) ^ Vector128.LoadUnsafe(ref sourceRef, offset)).StoreUnsafe(ref destinationRef, offset);
				i += Vector128<byte>.Count;
				left -= Vector128<byte>.Count;
			}
		}

		while (left >= sizeof(ulong))
		{
			ref readonly ulong v0 = ref Unsafe.Add(ref streamRef, i).As<ulong>();
			ref readonly ulong v1 = ref Unsafe.Add(ref sourceRef, i).As<ulong>();
			ref ulong dst = ref Unsafe.Add(ref destinationRef, i).As<ulong>();

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref readonly uint v0 = ref Unsafe.Add(ref streamRef, i).As<uint>();
			ref readonly uint v1 = ref Unsafe.Add(ref sourceRef, i).As<uint>();
			ref uint dst = ref Unsafe.Add(ref destinationRef, i).As<uint>();

			dst = v0 ^ v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			Unsafe.Add(ref destinationRef, i) = (byte)(Unsafe.Add(ref sourceRef, i) ^ Unsafe.Add(ref streamRef, i));
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
			ref readonly ulong v0 = ref Unsafe.Add(ref streamRef, i).As<ulong>();
			ref readonly ulong v1 = ref Unsafe.Add(ref sourceRef, i).As<ulong>();
			ref ulong dst = ref Unsafe.Add(ref destinationRef, i).As<ulong>();

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		if (left >= sizeof(uint))
		{
			ref readonly uint v0 = ref Unsafe.Add(ref streamRef, i).As<uint>();
			ref readonly uint v1 = ref Unsafe.Add(ref sourceRef, i).As<uint>();
			ref uint dst = ref Unsafe.Add(ref destinationRef, i).As<uint>();

			dst = v0 ^ v1;
			i += sizeof(uint);
		}

		for (; i < length; ++i)
		{
			Unsafe.Add(ref destinationRef, i) = (byte)(Unsafe.Add(ref sourceRef, i) ^ Unsafe.Add(ref streamRef, i));
		}
	}
}
