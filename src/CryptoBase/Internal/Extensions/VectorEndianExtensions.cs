namespace CryptoBase.Internal.Extensions;

internal static class VectorEndianExtensions
{
	extension<T>(Vector512<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> ReverseEndianness128()
		{
			Vector512<byte> vReverse128 = Vector512.Create
			(
				(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
				47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32,
				63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48
			);

			return Vector512.Shuffle(value.AsByte(), vReverse128).As<byte, T>();
		}
	}

	extension<T>(Vector256<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> ReverseEndianness128()
		{
			Vector256<byte> vReverse128 = Vector256.Create
			(
				(byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
				31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16
			);
			return Vector256.Shuffle(value.AsByte(), vReverse128).As<byte, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> ReverseEndianness32()
		{
			Vector256<byte> vReverse32 = Vector256.Create
			(
				(byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
				19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28
			);
			return Vector256.Shuffle(value.AsByte(), vReverse32).As<byte, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> ReverseEndianness64()
		{
			Vector256<byte> vReverse64 = Vector256.Create
			(
				(byte)7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
				23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24
			);
			return Vector256.Shuffle(value.AsByte(), vReverse64).As<byte, T>();
		}
	}

	extension<T>(Vector128<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> ReverseEndianness128()
		{
			if (AdvSimd.IsSupported)
			{
				Vector128<ulong> reversedLanes = AdvSimd.ReverseElement8(value.AsUInt64());
				return AdvSimd.ExtractVector128(reversedLanes, reversedLanes, 1).As<ulong, T>();
			}

			if (Sse2.IsSupported && !Ssse3.IsSupported)
			{
				Vector128<ushort> v = value.AsUInt16();
				v = v << 8 | v >>> 8;

				v = Sse2.ShuffleLow(v, 0b00_01_10_11);
				v = Sse2.ShuffleHigh(v, 0b00_01_10_11);

				return Vector128.Shuffle(v.AsUInt32(), Vector128.Create(2u, 3, 0, 1)).As<uint, T>();
			}

			Vector128<byte> reverse128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
			return Vector128.Shuffle(value.AsByte(), reverse128).As<byte, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> ReverseEndianness64()
		{
			if (AdvSimd.IsSupported)
			{
				return AdvSimd.ReverseElement8(value.AsUInt64()).As<ulong, T>();
			}

			if (Sse2.IsSupported && !Ssse3.IsSupported)
			{
				Vector128<ushort> v = value.AsUInt16();
				v = v << 8 | v >>> 8;

				v = Sse2.ShuffleLow(v, 0b00_01_10_11);
				return Sse2.ShuffleHigh(v, 0b00_01_10_11).As<ushort, T>();
			}

			Vector128<byte> reverse64 = Vector128.Create((byte)7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
			return Vector128.Shuffle(value.AsByte(), reverse64).As<byte, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> ReverseEndianness32()
		{
			if (AdvSimd.IsSupported)
			{
				return AdvSimd.ReverseElement8(value.AsUInt32()).As<uint, T>();
			}

			if (Sse2.IsSupported && !Ssse3.IsSupported)
			{
				Vector128<ushort> v = value.AsUInt16();
				v = v << 8 | v >>> 8;

				v = Sse2.ShuffleLow(v, 0b10_11_00_01);
				v = Sse2.ShuffleHigh(v, 0b10_11_00_01);

				return v.As<ushort, T>();
			}

			Vector128<byte> reverse32 = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
			return Vector128.Shuffle(value.AsByte(), reverse32).As<byte, T>();
		}
	}
}
