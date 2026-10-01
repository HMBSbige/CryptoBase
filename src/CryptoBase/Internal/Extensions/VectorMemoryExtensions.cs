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
	}
}
