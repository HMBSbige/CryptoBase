using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class IntrinsicsUtils
	{
		private readonly static Vector256<byte> Rot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		private readonly static Vector256<byte> Rot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint AndNot(uint left, uint right)
		{
			if (Bmi1.IsSupported)
			{
				return Bmi1.AndNot(left, right);
			}
			return ~left & right;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector256<uint> RotateLeft(this Vector256<uint> value, byte offset)
		{
			return Avx2.Or(Avx2.ShiftLeftLogical(value, offset), Avx2.ShiftRightLogical(value, (byte)(32 - offset)));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector256<uint> RotateLeft8(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot8).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static Vector256<uint> RotateLeft16(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot16).AsUInt32();
		}
	}
}
