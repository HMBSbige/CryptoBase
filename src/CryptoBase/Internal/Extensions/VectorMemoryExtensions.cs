namespace CryptoBase.Internal.Extensions;

internal static class VectorMemoryExtensions
{
	extension(Vector128)
	{
		// Loads 1 to 16 bytes into the low elements of a zero vector without reading past them.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> LoadPartialUnsafe(ref byte source, nuint elementOffset, int length)
		{
			Debug.Assert(length is > 0 and <= 16);
			ref byte input = ref Unsafe.Add(ref source, elementOffset);

			if (length >= 8)
			{
				// The second read ends at the last byte, and the shift drops the bytes the first read covers.
				ulong low = Unsafe.ReadUnaligned<ulong>(ref input);
				ulong high = length is 8 ? 0 : Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref input, length - 8)) >> (16 - length) * 8;
				return Vector128.CreateUInt64(low, high).AsByte();
			}

			if (length >= 4)
			{
				ulong first = Unsafe.ReadUnaligned<uint>(ref input);
				ulong last = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, length - 4));
				return Vector128.CreateScalar(first | last << (length - 4) * 8).AsByte();
			}

			if (length >= 2)
			{
				uint first = Unsafe.ReadUnaligned<ushort>(ref input);
				uint last = Unsafe.Add(ref input, length - 1);
				return Vector128.CreateScalar(first | last << (length - 1) * 8).AsByte();
			}

			return Vector128.CreateScalar(input);
		}

		// The 16 bytes at offset, a multiple of 16, of the input zero-padded past length, without reading past the input.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> LoadZeroPaddedUnsafe(ref byte source, int offset, int length)
		{
			Debug.Assert(offset >= 0 && offset % 16 is 0 && length >= 0);

			if (offset is 0)
			{
				return length switch
				{
					>= 16 => Vector128.LoadUnsafe(ref source),
					0 => Vector128<byte>.Zero,
					_ => Vector128.LoadPartialUnsafe(ref source, 0, length)
				};
			}

			if (length >= offset + 16)
			{
				return Vector128.LoadUnsafe(ref source, (uint)offset);
			}

			if (length <= offset)
			{
				return Vector128<byte>.Zero;
			}

			// The input is at least 16 bytes long here, so its last 16 bytes hold the piece shift = offset + 16 - length places higher;
			// the indices that start shift places into ShiftDownIndices move them down and zero the rest.
			Vector128<byte> indices = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(ShiftDownIndices), (uint)(offset + 16 - length));
			return Vector128.ShuffleNative(Vector128.LoadUnsafe(ref source, (uint)(length - 16)), indices);
		}
	}

	// Sixteen indices in order, then indices with the high bit set, which select zero on x86 and, being out of range, on ARM64.
	private static ReadOnlySpan<byte> ShiftDownIndices =>
	[
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
	];

	extension(Vector128<byte> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void StorePartialUnsafe(ref byte destination, nuint elementOffset, int length)
		{
			Debug.Assert(length is > 0 and <= 16);
			ref byte output = ref Unsafe.Add(ref destination, elementOffset);
			ulong low = value.AsUInt64().ToScalar();

			if (length >= 8)
			{
				// The second store ends at the last byte; its shuffle indices stay in range for the stored elements.
				Vector128<byte> end = Vector128.ShuffleNative(value, Vector128<byte>.Indices + Vector128.Create((byte)(length - 8)));
				Unsafe.WriteUnaligned(ref output, low);
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, length - 8), end.AsUInt64().ToScalar());
				return;
			}

			if (length >= 4)
			{
				Unsafe.WriteUnaligned(ref output, (uint)low);
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, length - 4), (uint)(low >> (length - 4) * 8));
				return;
			}

			if (length >= 2)
			{
				Unsafe.WriteUnaligned(ref output, (ushort)low);
				Unsafe.Add(ref output, length - 1) = (byte)(low >> (length - 1) * 8);
				return;
			}

			output = (byte)low;
		}
	}
}
