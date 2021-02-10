using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class IntrinsicsUtils
	{
		private static readonly Vector256<byte> Rot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		private static readonly Vector256<byte> Rot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		private static readonly Vector128<byte> Rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		private static readonly Vector128<byte> Rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		private static readonly Vector128<byte> Rot24_128 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
		private static readonly Vector128<byte> Reverse32 = Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
		private static readonly Vector128<byte> Reverse_128 = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static uint AndNot(uint left, uint right)
		{
			if (Bmi1.IsSupported)
			{
				return Bmi1.AndNot(left, right);
			}
			return ~left & right;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector256<uint> RotateLeftUInt32(this Vector256<uint> value, byte offset)
		{
			return Avx2.Or(Avx2.ShiftLeftLogical(value, offset), Avx2.ShiftRightLogical(value, (byte)(32 - offset)));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector256<uint> RotateLeftUInt32_8(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot8).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector256<uint> RotateLeftUInt32_16(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot16).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeftUInt32(this Vector128<uint> value, byte offset)
		{
			return Sse2.Or(Sse2.ShiftLeftLogical(value, offset), Sse2.ShiftRightLogical(value, (byte)(32 - offset)));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeftUInt32_8(this Vector128<uint> value)
		{
			return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot8_128).AsUInt32() : value.RotateLeftUInt32(8);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeftUInt32_16(this Vector128<uint> value)
		{
			return Ssse3.IsSupported ? Ssse3.Shuffle(value.AsByte(), Rot16_128).AsUInt32() : value.RotateLeftUInt32(16);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> RotateLeftUInt32_8(this Vector128<byte> value)
		{
			return Ssse3.Shuffle(value, Rot8_128);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> RotateLeftUInt32_16(this Vector128<byte> value)
		{
			return Ssse3.Shuffle(value, Rot16_128);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> RotateLeftUInt32_24(this Vector128<byte> value)
		{
			return Ssse3.Shuffle(value, Rot24_128);
		}

		/// <summary>
		/// destination = source ^ stream
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
		{
			if (Avx.IsSupported)
			{
				while (length >= 32)
				{
					var v0 = Avx.LoadVector256(stream);
					var v1 = Avx.LoadVector256(source);
					Avx.Store(destination, Avx2.Xor(v0, v1));

					stream += 32;
					source += 32;
					destination += 32;
					length -= 32;
				}
			}

			if (Sse2.IsSupported)
			{
				while (length >= 16)
				{
					var v0 = Sse2.LoadVector128(stream);
					var v1 = Sse2.LoadVector128(source);
					Sse2.Store(destination, Sse2.Xor(v0, v1));

					stream += 16;
					source += 16;
					destination += 16;
					length -= 16;
				}
			}

			XorSoftwareFallback(stream, source, destination, length);
		}

		/// <summary>
		/// destination = source ^ stream
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void Xor16(byte* stream, byte* source, byte* destination)
		{
			if (Sse2.IsSupported)
			{
				var v0 = Sse2.LoadVector128(stream);
				var v1 = Sse2.LoadVector128(source);
				Sse2.Store(destination, Sse2.Xor(v0, v1));
			}
			else
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

		/// <summary>
		/// destination = source ^ stream
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void XorSoftwareFallback(byte* stream, byte* source, byte* destination, int length)
		{
			for (var i = 0; i < length; ++i)
			{
				*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> ReverseEndianness32(this Vector128<byte> value)
		{
			return Ssse3.Shuffle(value, Reverse32);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> ReverseEndianness32(this Vector128<uint> value)
		{
			return Ssse3.Shuffle(value.AsByte(), Reverse32);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> Xor(this Vector128<byte> a, Vector128<byte> b)
		{
			return Sse2.Xor(a, b);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<byte> Reverse(this Vector128<byte> a)
		{
			return Ssse3.Shuffle(a, Reverse_128);
		}
	}
}
