using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class ChaCha20Utils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void UpdateKeyStream(int rounds, uint[] state, byte[] keyStream)
		{
			var x = ArrayPool<uint>.Shared.Rent(SnuffleCryptoBase.StateSize);
			try
			{
				state.AsSpan().CopyTo(x);

				ChaChaRound(rounds, x);

				for (var i = 0; i < SnuffleCryptoBase.StateSize; i += 4)
				{
					x[i] += state[i];
					x[i + 1] += state[i + 1];
					x[i + 2] += state[i + 2];
					x[i + 3] += state[i + 3];
				}

				var span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, 64));
				x.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(span);
			}
			finally
			{
				ArrayPool<uint>.Shared.Return(x);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void ChaChaRound(int rounds, uint[] x)
		{
			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
				QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
				QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
				QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);

				QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
				QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
				QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
				QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
		{
			Step(ref a, ref b, ref d, 16);
			Step(ref c, ref d, ref b, 12);
			Step(ref a, ref b, ref d, 8);
			Step(ref c, ref d, ref b, 7);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Step(ref uint a, ref uint b, ref uint c, byte i)
		{
			a += b;
			c = (a ^ c).RotateLeft(i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
		{
			a = Sse2.Add(a, b);
			d = Sse2.Xor(a, d).RotateLeft16();

			c = Sse2.Add(c, d);
			b = Sse2.Xor(b, c).RotateLeft(12);

			a = Sse2.Add(a, b);
			d = Sse2.Xor(a, d).RotateLeft8();

			c = Sse2.Add(c, d);
			b = Sse2.Xor(b, c).RotateLeft(7);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
		{
			a = Avx2.Add(a, b);
			d = Avx2.Xor(a, d).RotateLeft16();

			c = Avx2.Add(c, d);
			b = Avx2.Xor(b, c).RotateLeft(12);

			a = Avx2.Add(a, b);
			d = Avx2.Xor(a, d).RotateLeft8();

			c = Avx2.Add(c, d);
			b = Avx2.Xor(b, c).RotateLeft(7);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void UpdateKeyStream(uint* state, byte* stream, byte rounds)
		{
			var s0 = Sse2.LoadVector128(state);
			var s1 = Sse2.LoadVector128(state + 4);
			var s2 = Sse2.LoadVector128(state + 8);
			var s3 = Sse2.LoadVector128(state + 12);

			var x0 = s0;
			var x1 = s1;
			var x2 = s2;
			var x3 = s3;

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			x0 = Sse2.Add(x0, s0);
			x1 = Sse2.Add(x1, s1);
			x2 = Sse2.Add(x2, s2);
			x3 = Sse2.Add(x3, s3);

			Sse2.Store(stream, x0.AsByte());
			Sse2.Store(stream + 16, x1.AsByte());
			Sse2.Store(stream + 32, x2.AsByte());
			Sse2.Store(stream + 48, x3.AsByte());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaRound(uint* state, byte rounds)
		{
			var x0 = Sse2.LoadVector128(state);
			var x1 = Sse2.LoadVector128(state + 4);
			var x2 = Sse2.LoadVector128(state + 8);
			var x3 = Sse2.LoadVector128(state + 12);

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			Sse2.Store(state, x0);
			Sse2.Store(state + 4, x1);
			Sse2.Store(state + 8, x2);
			Sse2.Store(state + 12, x3);
		}

		/// <summary>
		/// 4 5 6 7
		/// 8 9 10 11
		/// 12 13 14 15
		/// =>
		/// 5 6 7 4
		/// 10 11 8 9
		/// 15 12 13 14
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Shuffle(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
		{
			a = Sse2.Shuffle(a, 0b00_11_10_01);
			b = Sse2.Shuffle(b, 0b01_00_11_10);
			c = Sse2.Shuffle(c, 0b10_01_00_11);
		}

		/// <summary>
		/// 5 6 7 4
		/// 10 11 8 9
		/// 15 12 13 14
		/// =>
		/// 4 5 6 7
		/// 8 9 10 11
		/// 12 13 14 15
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Shuffle1(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c)
		{
			a = Sse2.Shuffle(a, 0b10_01_00_11);
			b = Sse2.Shuffle(b, 0b01_00_11_10);
			c = Sse2.Shuffle(c, 0b00_11_10_01);
		}

		/// <summary>
		/// 处理 64 bytes
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore64(byte rounds, uint* state, byte* source, byte* destination)
		{
			var s0 = Sse2.LoadVector128(state);
			var s1 = Sse2.LoadVector128(state + 4);
			var s2 = Sse2.LoadVector128(state + 8);
			var s3 = Sse2.LoadVector128(state + 12);

			var x0 = s0;
			var x1 = s1;
			var x2 = s2;
			var x3 = s3;

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			x0 = Sse2.Add(x0, s0);
			x1 = Sse2.Add(x1, s1);
			x2 = Sse2.Add(x2, s2);
			x3 = Sse2.Add(x3, s3);

			var v0 = Sse2.Xor(x0.AsByte(), Sse2.LoadVector128(source));
			var v1 = Sse2.Xor(x1.AsByte(), Sse2.LoadVector128(source + 16));
			var v2 = Sse2.Xor(x2.AsByte(), Sse2.LoadVector128(source + 32));
			var v3 = Sse2.Xor(x3.AsByte(), Sse2.LoadVector128(source + 48));

			Sse2.Store(destination, v0);
			Sse2.Store(destination + 16, v1);
			Sse2.Store(destination + 32, v2);
			Sse2.Store(destination + 48, v3);

			if (++*(state + 12) == 0)
			{
				++*(state + 13);
			}
		}

		/// <summary>
		/// 处理 128 bytes
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore128(byte rounds, uint* state, byte* source, byte* destination)
		{
			var t12 = *(state + 12);
			var t13 = *(state + 13);
			var s1 = Avx.LoadVector256(state + 8); // 8 9 10 11 12 13 14 15

			if (++*(state + 12) == 0)
			{
				++*(state + 13);
			}

			var x0 = Vector256.Create(
				*(state + 0), *(state + 1), *(state + 2), *(state + 3),
				*(state + 0), *(state + 1), *(state + 2), *(state + 3));
			var x1 = Vector256.Create(
					*(state + 4), *(state + 5), *(state + 6), *(state + 7),
					*(state + 4), *(state + 5), *(state + 6), *(state + 7));
			var x2 = Vector256.Create(
					*(state + 8), *(state + 9), *(state + 10), *(state + 11),
					*(state + 8), *(state + 9), *(state + 10), *(state + 11));
			var x3 = Vector256.Create(
					t12, t13, *(state + 14), *(state + 15),
					*(state + 12), *(state + 13), *(state + 14), *(state + 15));

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			Shuffle(ref x0, ref x1, ref x2, ref x3);

			var s0 = Avx.LoadVector256(state); // 0 1 2 3 4 5 6 7

			x0 = Avx2.Add(x0, s0);
			x1 = Avx2.Add(x1, s1);
			x2 = Avx2.Add(x2, s0);
			x3 = Avx2.Add(x3, Avx.LoadVector256(state + 8));

			var v0 = Avx2.Xor(x0.AsByte(), Avx.LoadVector256(source));
			var v1 = Avx2.Xor(x1.AsByte(), Avx.LoadVector256(source + 32));
			var v2 = Avx2.Xor(x2.AsByte(), Avx.LoadVector256(source + 64));
			var v3 = Avx2.Xor(x3.AsByte(), Avx.LoadVector256(source + 96));

			Avx.Store(destination, v0);
			Avx.Store(destination + 32, v1);
			Avx.Store(destination + 64, v2);
			Avx.Store(destination + 96, v3);

			if (++*(state + 12) == 0)
			{
				++*(state + 13);
			}
		}

		#region Avx

		private static readonly Vector256<uint> Permute0 = Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4).AsUInt32();
		private static readonly Vector256<uint> Permute1 = Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5).AsUInt32();
		private static readonly Vector256<uint> Permute2 = Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6).AsUInt32();
		private static readonly Vector256<uint> Permute3 = Vector256.Create(0, 1, 4, 5, 2, 3, 6, 7).AsUInt32();

		/// <summary>
		/// 4 5 6 7
		/// 8 9 10 11
		/// 12 13 14 15
		/// =>
		/// 5 6 7 4
		/// 10 11 8 9
		/// 15 12 13 14
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c)
		{
			a = Avx2.PermuteVar8x32(a, Permute0);
			b = Avx2.PermuteVar8x32(b, Permute1);
			c = Avx2.PermuteVar8x32(c, Permute2);
		}

		/// <summary>
		/// 5 6 7 4
		/// 10 11 8 9
		/// 15 12 13 14
		/// =>
		/// 4 5 6 7
		/// 8 9 10 11
		/// 12 13 14 15
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Shuffle1(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c)
		{
			a = Avx2.PermuteVar8x32(a, Permute2);
			b = Avx2.PermuteVar8x32(b, Permute1);
			c = Avx2.PermuteVar8x32(c, Permute0);
		}

		/// <summary>
		/// 0 1 2 3 16 17 18 19
		/// 4 5 6 7 20 21 22 23
		/// 8 9 10 11 24 25 26 27
		/// 12 13 14 15 28 29 30 31
		/// =>
		/// 0 1 2 3 4 5 6 7
		/// 8 9 10 11 12 13 14 15
		/// 16 17 18 19 20 21 22 23
		/// 24 25 26 27 28 29 30 31
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Shuffle(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
		{
			a = Avx2.PermuteVar8x32(a, Permute3);
			b = Avx2.PermuteVar8x32(b, Permute3);
			c = Avx2.PermuteVar8x32(c, Permute3);
			d = Avx2.PermuteVar8x32(d, Permute3);

			var t0 = Avx2.PermuteVar8x32(Avx2.UnpackLow(a.AsUInt64(), b.AsUInt64()).AsUInt32(), Permute3);
			var t1 = Avx2.PermuteVar8x32(Avx2.UnpackHigh(a.AsUInt64(), b.AsUInt64()).AsUInt32(), Permute3);
			var t2 = Avx2.PermuteVar8x32(Avx2.UnpackLow(c.AsUInt64(), d.AsUInt64()).AsUInt32(), Permute3);
			var t3 = Avx2.PermuteVar8x32(Avx2.UnpackHigh(c.AsUInt64(), d.AsUInt64()).AsUInt32(), Permute3);

			a = t0;
			b = t2;
			c = t1;
			d = t3;
		}

		#endregion
	}
}
