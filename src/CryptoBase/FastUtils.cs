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

		while (left >= 2 * sizeof(ulong))
		{
			ref readonly ulong v0 = ref Unsafe.Add(ref streamRef, i).As<ulong>();
			ref readonly ulong v1 = ref Unsafe.Add(ref sourceRef, i).As<ulong>();
			ref ulong dst = ref Unsafe.Add(ref destinationRef, i).As<ulong>();

			dst = v0 ^ v1;
			i += sizeof(ulong);
			left -= sizeof(ulong);
		}

		XorTail(ref Unsafe.Add(ref streamRef, i), ref Unsafe.Add(ref sourceRef, i), ref Unsafe.Add(ref destinationRef, i), left);
	}

	/// <summary>
	/// destination = source ^ stream
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void XorLess16(ReadOnlySpan<byte> stream, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		XorTail(ref stream.GetReference(), ref source.GetReference(), ref destination.GetReference(), length);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorTail(ref byte stream, ref byte source, ref byte destination, int length)
	{
		Debug.Assert(length is >= 0 and < 2 * sizeof(ulong));

		if (length >= sizeof(ulong))
		{
			int last = length - sizeof(ulong);
			ulong first = Unsafe.ReadUnaligned<ulong>(ref stream) ^ Unsafe.ReadUnaligned<ulong>(ref source);
			ulong end = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stream, last)) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, last));
			Unsafe.WriteUnaligned(ref destination, first);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, last), end);
			return;
		}

		if (length >= sizeof(uint))
		{
			int last = length - sizeof(uint);
			uint first = Unsafe.ReadUnaligned<uint>(ref stream) ^ Unsafe.ReadUnaligned<uint>(ref source);
			uint end = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref stream, last)) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref source, last));
			Unsafe.WriteUnaligned(ref destination, first);
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, last), end);
			return;
		}

		if (length >= sizeof(ushort))
		{
			int last = length - 1;
			ushort first = (ushort)(Unsafe.ReadUnaligned<ushort>(ref stream) ^ Unsafe.ReadUnaligned<ushort>(ref source));
			byte end = (byte)(Unsafe.Add(ref stream, last) ^ Unsafe.Add(ref source, last));
			Unsafe.WriteUnaligned(ref destination, first);
			Unsafe.Add(ref destination, last) = end;
			return;
		}

		if (length > 0)
		{
			destination = (byte)(stream ^ source);
		}
	}
}
