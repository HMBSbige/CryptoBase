using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class IntrinsicsUtils
	{
		private readonly static Vector256<byte> Rot8 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		private readonly static Vector256<byte> Rot16 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		private readonly static Vector128<byte> Rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
		private readonly static Vector128<byte> Rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

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
		public static Vector256<uint> RotateLeft(this Vector256<uint> value, byte offset)
		{
			return Avx2.Or(Avx2.ShiftLeftLogical(value, offset), Avx2.ShiftRightLogical(value, (byte)(32 - offset)));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector256<uint> RotateLeft8(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot8).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector256<uint> RotateLeft16(this Vector256<uint> value)
		{
			return Avx2.Shuffle(value.AsByte(), Rot16).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeft(this Vector128<uint> value, byte offset)
		{
			return Sse2.Or(Sse2.ShiftLeftLogical(value, offset), Sse2.ShiftRightLogical(value, (byte)(32 - offset)));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeft8(this Vector128<uint> value)
		{
			return Ssse3.Shuffle(value.AsByte(), Rot8_128).AsUInt32();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static Vector128<uint> RotateLeft16(this Vector128<uint> value)
		{
			return Ssse3.Shuffle(value.AsByte(), Rot16_128).AsUInt32();
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

			for (var i = 0; i < length; ++i)
			{
				*(destination + i) = (byte)(*(source + i) ^ *(stream + i));
			}
		}

		#region Salsa

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void SalsaQuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
		{
			a = Sse2.Xor(a, Sse2.Add(b, c).RotateLeft(7));
			d = Sse2.Xor(d, Sse2.Add(a, b).RotateLeft(9));
			c = Sse2.Xor(c, Sse2.Add(d, a).RotateLeft(13));
			b = Sse2.Xor(b, Sse2.Add(c, d).RotateLeft(18));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void SalsaCore(uint* state, byte* stream, byte rounds)
		{
			if (Avx.IsSupported && Avx2.IsSupported)
			{
				SalsaCoreAvx(state, stream, rounds);
				return;
			}
			var s0 = Sse2.LoadVector128(state);
			var s1 = Sse2.LoadVector128(state + 4);
			var s2 = Sse2.LoadVector128(state + 8);
			var s3 = Sse2.LoadVector128(state + 12);

			var x0 = Vector128.Create(*(state + 4), *(state + 9), *(state + 14), *(state + 3)); // 4 9 14 3
			var x1 = Vector128.Create(*(state + 0), *(state + 5), *(state + 10), *(state + 15)); // 0 5 10 15
			var x2 = Vector128.Create(*(state + 12), *(state + 1), *(state + 6), *(state + 11)); // 12 1 6 11
			var x3 = Vector128.Create(*(state + 8), *(state + 13), *(state + 2), *(state + 7)); // 8 13 2 7

			for (var i = 0; i < rounds; i += 2)
			{
				SalsaQuarterRound(ref x0, ref x1, ref x2, ref x3);
				SalsaShuffle(ref x0, ref x2, ref x3);

				SalsaQuarterRound(ref x0, ref x1, ref x2, ref x3);
				SalsaShuffle(ref x0, ref x2, ref x3);
			}

			SalsaShuffle(ref x0, ref x1, ref x2, ref x3);

			x0 = Sse2.Add(x0, s0);
			x1 = Sse2.Add(x1, s1);
			x2 = Sse2.Add(x2, s2);
			x3 = Sse2.Add(x3, s3);

			Sse2.Store(stream, x0.AsByte());
			Sse2.Store(stream + 16, x1.AsByte());
			Sse2.Store(stream + 32, x2.AsByte());
			Sse2.Store(stream + 48, x3.AsByte());

			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}

		/// <summary>
		/// 0 1 2 3
		/// 4 5 6 7
		/// 8 9 10 11
		/// =>
		/// 5 6 7 4
		/// 3 0 1 2
		/// 10 11 8 9
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void SalsaShuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
		{
			Utils.Swap(ref a, ref b);
			a = Sse2.Shuffle(a, 0b00_11_10_01);
			b = Sse2.Shuffle(b, 0b10_01_00_11);
			c = Sse2.Shuffle(c, 0b01_00_11_10);
		}

		/// <summary>
		/// 4 9 14 3
		/// 0 5 10 15
		/// 12 1 6 11
		/// 8 13 2 7
		/// =>
		/// 0 1 2 3
		/// 4 5 6 7
		/// 8 9 10 11
		/// 12 13 14 15
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void SalsaShuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
		{
			a = Sse2.Shuffle(a, 0b10_01_00_11); // 4 9 14 3 => 3 4 9 14
												// 0 5 10 15
			c = Sse2.Shuffle(c, 0b00_11_10_01); // 12 1 6 11 => 1 6 11 12
			d = Sse2.Shuffle(d, 0b01_00_11_10); // 8 13 2 7 => 2 7 8 13

			var t0 = Sse2.UnpackLow(a, b); // 3 0 4 5
			var t1 = Sse2.UnpackLow(c, d); // 1 2 6 7
			var t2 = Sse2.UnpackHigh(a, b); // 9 10 14 15
			var t3 = Sse2.UnpackHigh(c, d); // 11 8 12 13

			a = Sse2.Shuffle(Sse2.UnpackLow(t0, t1), 0b00_11_01_10); // 3 1 0 2 => 0 1 2 3
			b = Sse2.Shuffle(Sse2.UnpackHigh(t0, t1), 0b11_01_10_00); // 4 6 5 7 => 4 5 6 7
			c = Sse2.Shuffle(Sse2.UnpackLow(t2, t3), 0b01_10_00_11); // 9 11 10 8 => 8 9 10 11
			d = Sse2.Shuffle(Sse2.UnpackHigh(t2, t3), 0b10_00_11_01); // 14 12 15 13 => 12 13 14 15
		}

		#endregion

		#region SalsaAvx

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void SalsaCoreAvx(uint* state, byte* stream, byte rounds)
		{
			var s0 = Avx.LoadVector256(state);
			var s1 = Avx.LoadVector256(state + 8);

			var x0 = Vector128.Create(*(state + 4), *(state + 9), *(state + 14), *(state + 3)); // 4 9 14 3
			var x1 = Vector128.Create(*(state + 0), *(state + 5), *(state + 10), *(state + 15)); // 0 5 10 15
			var x2 = Vector128.Create(*(state + 12), *(state + 1), *(state + 6), *(state + 11)); // 12 1 6 11
			var x3 = Vector128.Create(*(state + 8), *(state + 13), *(state + 2), *(state + 7)); // 8 13 2 7

			for (var i = 0; i < rounds; i += 2)
			{
				SalsaQuarterRound(ref x0, ref x1, ref x2, ref x3);
				SalsaShuffle(ref x0, ref x2, ref x3);

				SalsaQuarterRound(ref x0, ref x1, ref x2, ref x3);
				SalsaShuffle(ref x0, ref x2, ref x3);
			}

			SalsaShuffleAvx(ref x0, ref x1, ref x2, ref x3, out var a, out var b);

			a = Avx2.Add(a, s0);
			b = Avx2.Add(b, s1);

			Avx.Store(stream, a.AsByte());
			Avx.Store(stream + 32, b.AsByte());

			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}

		private static readonly Vector256<uint> Permute0 = Vector256.Create(4, 3, 1, 6, 0, 5, 2, 7).AsUInt32();
		private static readonly Vector256<uint> Permute1 = Vector256.Create(1, 6, 4, 3, 2, 7, 0, 5).AsUInt32();
		private static readonly Vector256<uint> Permute2 = Vector256.Create(0, 1, 3, 2, 4, 6, 5, 7).AsUInt32();
		private static readonly Vector256<uint> Permute3 = Vector256.Create(1, 0, 2, 3, 5, 7, 4, 6).AsUInt32();

		/// <summary>
		/// 4 9 14 3
		/// 0 5 10 15
		/// 12 1 6 11
		/// 8 13 2 7
		/// =>
		/// 0 1 2 3 4 5 6 7
		/// 8 9 10 11 12 13 14 15
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void SalsaShuffleAvx(
			ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d,
			out Vector256<uint> x0, out Vector256<uint> x1)
		{
			x0 = Vector256.Create(a, b); // 4 9 14 3 0 5 10 15
			x1 = Vector256.Create(c, d); // 12 1 6 11 8 13 2 7

			x0 = Avx2.PermuteVar8x32(x0, Permute0); // 0 3 9 10 4 5 14 15
			x1 = Avx2.PermuteVar8x32(x1, Permute1); // 1 2 8 11 6 7 12 13

			var t = Avx2.UnpackLow(x0, x1); // 0 1 3 2 4 6 5 7
			x1 = Avx2.UnpackHigh(x0, x1); // 9 8 10 11 14 12 15 13

			x0 = Avx2.PermuteVar8x32(t, Permute2); // 0 1 2 3 4 5 6 7
			x1 = Avx2.PermuteVar8x32(x1, Permute3); // 8 9 10 11 12 13 14 15
		}

		#endregion
	}
}
