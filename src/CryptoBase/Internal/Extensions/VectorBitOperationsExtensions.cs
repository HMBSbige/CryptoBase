using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Internal.Extensions;

internal static class VectorBitOperationsExtensions
{
	extension<T>(Vector512<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector512<T> RotateLeftUInt32([ConstantExpected(Min = 1, Max = 31)] byte offset)
		{
			return Avx512F.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
		}
	}

	extension<T>(Vector256<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> RotateLeftUInt32([ConstantExpected(Min = 1, Max = 31)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
			}

			if (Avx2.IsSupported && offset is 8 or 16 or 24)
			{
				Vector128<byte> indices = CreateRotateLeftUInt32ShuffleIndices(offset);
				return Avx2.Shuffle(value.AsByte(), Vector256.Create(indices)).As<byte, T>();
			}

			return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> RotateRightUInt32([ConstantExpected(Min = 1, Max = 31)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateRight(value.AsUInt32(), offset).As<uint, T>();
			}

			if (Avx2.IsSupported && offset is 8 or 16 or 24)
			{
				Vector128<byte> indices = CreateRotateLeftUInt32ShuffleIndices((byte)(32 - offset));
				return Avx2.Shuffle(value.AsByte(), Vector256.Create(indices)).As<byte, T>();
			}

			return (value.AsUInt32() >>> offset | value.AsUInt32() << 32 - offset).As<uint, T>();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector256<T> RotateRightUInt64([ConstantExpected(Min = 1, Max = 63)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateRight(value.AsUInt64(), offset).As<ulong, T>();
			}

			if (Avx2.IsSupported && (offset & 7) is 0)
			{
				return RotateRightUInt64ByWholeBytes(value, offset);
			}

			return (value.AsUInt64() >>> offset | value.AsUInt64() << 64 - offset).As<ulong, T>();
		}
	}

	extension<T>(Vector128<T> value)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Vector128<T> RotateLeftUInt32([ConstantExpected(Min = 1, Max = 31)] byte offset)
		{
			if (Avx512F.VL.IsSupported)
			{
				return Avx512F.VL.RotateLeft(value.AsUInt32(), offset).As<uint, T>();
			}

			if (Ssse3.IsSupported && offset is 8 or 16 or 24)
			{
				Vector128<byte> indices = CreateRotateLeftUInt32ShuffleIndices(offset);
				return Ssse3.Shuffle(value.AsByte(), indices).As<byte, T>();
			}

			if (AdvSimd.IsSupported)
			{
#pragma warning disable CA1857
				// ReSharper disable once ConstantExpected
				return AdvSimd.ShiftRightAndInsert(value.AsUInt32() << offset, value.AsUInt32(), (byte)(32 - offset)).As<uint, T>();
#pragma warning restore CA1857
			}

			return (value.AsUInt32() << offset | value.AsUInt32() >>> 32 - offset).As<uint, T>();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> CreateRotateLeftUInt32ShuffleIndices(byte offset)
	{
		return offset switch
		{
			8 => Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14),
			16 => Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
			_ => Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12)
		};
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<T> RotateRightUInt64ByWholeBytes<T>(Vector256<T> value, byte offset)
	{
		if (offset is 32)
		{
			return Avx2.Shuffle(value.AsUInt32(), 0b10_11_00_01).As<uint, T>();
		}

		Vector128<byte> indices = CreateRotateRightUInt64ShuffleIndices(offset);
		return Avx2.Shuffle(value.AsByte(), Vector256.Create(indices)).As<byte, T>();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> CreateRotateRightUInt64ShuffleIndices(byte offset)
	{
		return offset switch
		{
			8 => Vector128.Create((byte)1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8),
			16 => Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9),
			24 => Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10),
			40 => Vector128.Create((byte)5, 6, 7, 0, 1, 2, 3, 4, 13, 14, 15, 8, 9, 10, 11, 12),
			48 => Vector128.Create((byte)6, 7, 0, 1, 2, 3, 4, 5, 14, 15, 8, 9, 10, 11, 12, 13),
			_ => Vector128.Create((byte)7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14)
		};
	}
}
