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
			d = Sse2.Xor(a, d).RotateLeftUInt32_16();

			c = Sse2.Add(c, d);
			b = Sse2.Xor(b, c).RotateLeftUInt32(12);

			a = Sse2.Add(a, b);
			d = Sse2.Xor(a, d).RotateLeftUInt32_8();

			c = Sse2.Add(c, d);
			b = Sse2.Xor(b, c).RotateLeftUInt32(7);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
		{
			a = Avx2.Add(a, b);
			d = Avx2.Xor(a, d).RotateLeftUInt32_16();

			c = Avx2.Add(c, d);
			b = Avx2.Xor(b, c).RotateLeftUInt32(12);

			a = Avx2.Add(a, b);
			d = Avx2.Xor(a, d).RotateLeftUInt32_8();

			c = Avx2.Add(c, d);
			b = Avx2.Xor(b, c).RotateLeftUInt32(7);
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
		public static unsafe void IncrementCounterOriginal(uint* state)
		{
			if (++*(state + 12) == 0)
			{
				++*(state + 13);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 12) == 0)
			{
				throw new InvalidOperationException(@"Data maximum length reached.");
			}
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

		#region 处理 64 bytes

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static unsafe void ChaChaCore64Internal(byte rounds, uint* state, byte* source, byte* destination)
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
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCoreOriginal64(byte rounds, uint* state, byte* source, byte* destination)
		{
			ChaChaCore64Internal(rounds, state, source, destination);

			IncrementCounterOriginal(state);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore64(byte rounds, uint* state, byte* source, byte* destination)
		{
			ChaChaCore64Internal(rounds, state, source, destination);

			IncrementCounter(state);
		}

		#endregion

		#region 处理 128 bytes

		private static readonly Vector256<uint> IncCounter128 = Vector256.Create(0, 0, 0, 0, 1, 0, 0, 0).AsUInt32();
		private static readonly Vector256<ulong> IncCounterOriginal128 = Vector256.Create(0, 0, 1, 0).AsUInt64();

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCoreOriginal128(byte rounds, uint* state, byte* source, byte* destination)
		{
			var x0 = Avx2.BroadcastVector128ToVector256(state);
			var x1 = Avx2.BroadcastVector128ToVector256(state + 4);
			var x2 = Avx2.BroadcastVector128ToVector256(state + 8);
			var x3 = Avx2.BroadcastVector128ToVector256(state + 12);
			x3 = Avx2.Add(x3.AsUInt64(), IncCounterOriginal128).AsUInt32();

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			Shuffle(ref x0, ref x1, ref x2, ref x3);

			var s0 = Avx.LoadVector256(state); // 0 1 2 3 4 5 6 7
			var s1 = Avx.LoadVector256(state + 8); // 8 9 10 11 12 13 14 15
			IncrementCounterOriginal(state);

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

			IncrementCounterOriginal(state);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore128(byte rounds, uint* state, byte* source, byte* destination)
		{
			var x0 = Avx2.BroadcastVector128ToVector256(state);
			var x1 = Avx2.BroadcastVector128ToVector256(state + 4);
			var x2 = Avx2.BroadcastVector128ToVector256(state + 8);
			var x3 = Avx2.BroadcastVector128ToVector256(state + 12);
			x3 = Avx2.Add(x3, IncCounter128);

			for (var i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle(ref x1, ref x2, ref x3);

				QuarterRound(ref x0, ref x1, ref x2, ref x3);
				Shuffle1(ref x1, ref x2, ref x3);
			}

			Shuffle(ref x0, ref x1, ref x2, ref x3);

			var s0 = Avx.LoadVector256(state); // 0 1 2 3 4 5 6 7
			var s1 = Avx.LoadVector256(state + 8); // 8 9 10 11 12 13 14 15
			IncrementCounter(state);

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

			IncrementCounter(state);
		}

		#endregion

		#region 处理 256*n bytes

		private static readonly Vector128<ulong> IncCounter01 = Vector128.Create(0ul, 1);
		private static readonly Vector128<ulong> IncCounter23 = Vector128.Create(2ul, 3);
		private static readonly Vector128<uint> IncCounter0123_128 = Vector128.Create(0u, 1, 2, 3);

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCoreOriginal256(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			var o0 = Vector128.Create(*(state + 0));
			var o1 = Vector128.Create(*(state + 1));
			var o2 = Vector128.Create(*(state + 2));
			var o3 = Vector128.Create(*(state + 3));
			var o4 = Vector128.Create(*(state + 4));
			var o5 = Vector128.Create(*(state + 5));
			var o6 = Vector128.Create(*(state + 6));
			var o7 = Vector128.Create(*(state + 7));
			var o8 = Vector128.Create(*(state + 8));
			var o9 = Vector128.Create(*(state + 9));
			var o10 = Vector128.Create(*(state + 10));
			var o11 = Vector128.Create(*(state + 11));
			// 12
			// 13
			var o14 = Vector128.Create(*(state + 14));
			var o15 = Vector128.Create(*(state + 15));

			while (length >= 256)
			{
				var x0 = o0;
				var x1 = o1;
				var x2 = o2;
				var x3 = o3;
				var x4 = o4;
				var x5 = o5;
				var x6 = o6;
				var x7 = o7;
				var x8 = o8;
				var x9 = o9;
				var x10 = o10;
				var x11 = o11;
				// 12
				// 13
				var x14 = o14;
				var x15 = o15;

				var counter = *(state + 12) | (ulong)*(state + 13) << 32;
				var t0 = Vector128.Create(counter).AsUInt32();
				var t1 = t0;

				var x12 = Sse2.Add(IncCounter01, t0.AsUInt64()).AsUInt32();
				var x13 = Sse2.Add(IncCounter23, t1.AsUInt64()).AsUInt32();

				t0 = Sse2.UnpackLow(x12, x13);
				t1 = Sse2.UnpackHigh(x12, x13);

				x12 = Sse2.UnpackLow(t0, t1);
				x13 = Sse2.UnpackHigh(t0, t1);

				var o12 = x12;
				var o13 = x13;

				counter += 4;

				*(state + 12) = (uint)(counter & 0xFFFFFFFF);
				*(state + 13) = (uint)(counter >> 32 & 0xFFFFFFFF);

				for (var i = 0; i < rounds; i += 2)
				{
					QuarterRound(ref x0, ref x4, ref x8, ref x12);
					QuarterRound(ref x1, ref x5, ref x9, ref x13);
					QuarterRound(ref x2, ref x6, ref x10, ref x14);
					QuarterRound(ref x3, ref x7, ref x11, ref x15);
					QuarterRound(ref x0, ref x5, ref x10, ref x15);
					QuarterRound(ref x1, ref x6, ref x11, ref x12);
					QuarterRound(ref x2, ref x7, ref x8, ref x13);
					QuarterRound(ref x3, ref x4, ref x9, ref x14);
				}

				AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, source, destination);
				AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, source + 16, destination + 16);
				AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, source + 32, destination + 32);
				AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, source + 48, destination + 48);

				length -= 256;
				destination += 256;
				source += 256;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore256(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			var o0 = Vector128.Create(*(state + 0));
			var o1 = Vector128.Create(*(state + 1));
			var o2 = Vector128.Create(*(state + 2));
			var o3 = Vector128.Create(*(state + 3));
			var o4 = Vector128.Create(*(state + 4));
			var o5 = Vector128.Create(*(state + 5));
			var o6 = Vector128.Create(*(state + 6));
			var o7 = Vector128.Create(*(state + 7));
			var o8 = Vector128.Create(*(state + 8));
			var o9 = Vector128.Create(*(state + 9));
			var o10 = Vector128.Create(*(state + 10));
			var o11 = Vector128.Create(*(state + 11));
			// 12
			var o13 = Vector128.Create(*(state + 13));
			var o14 = Vector128.Create(*(state + 14));
			var o15 = Vector128.Create(*(state + 15));

			while (length >= 256)
			{
				var x0 = o0;
				var x1 = o1;
				var x2 = o2;
				var x3 = o3;
				var x4 = o4;
				var x5 = o5;
				var x6 = o6;
				var x7 = o7;
				var x8 = o8;
				var x9 = o9;
				var x10 = o10;
				var x11 = o11;
				// 12
				var x13 = o13;
				var x14 = o14;
				var x15 = o15;

				var x12 = Sse2.Add(IncCounter0123_128, Vector128.Create(*(state + 12)));
				var o12 = x12;

				*(state + 12) += 4;

				for (var i = 0; i < rounds; i += 2)
				{
					QuarterRound(ref x0, ref x4, ref x8, ref x12);
					QuarterRound(ref x1, ref x5, ref x9, ref x13);
					QuarterRound(ref x2, ref x6, ref x10, ref x14);
					QuarterRound(ref x3, ref x7, ref x11, ref x15);
					QuarterRound(ref x0, ref x5, ref x10, ref x15);
					QuarterRound(ref x1, ref x6, ref x11, ref x12);
					QuarterRound(ref x2, ref x7, ref x8, ref x13);
					QuarterRound(ref x3, ref x4, ref x9, ref x14);
				}

				AddTransposeXor(ref x0, ref x1, ref x2, ref x3, ref o0, ref o1, ref o2, ref o3, source, destination);
				AddTransposeXor(ref x4, ref x5, ref x6, ref x7, ref o4, ref o5, ref o6, ref o7, source + 16, destination + 16);
				AddTransposeXor(ref x8, ref x9, ref x10, ref x11, ref o8, ref o9, ref o10, ref o11, source + 32, destination + 32);
				AddTransposeXor(ref x12, ref x13, ref x14, ref x15, ref o12, ref o13, ref o14, ref o15, source + 48, destination + 48);

				length -= 256;
				destination += 256;
				source += 256;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static unsafe void AddTransposeXor(
			ref Vector128<uint> x0, ref Vector128<uint> x1, ref Vector128<uint> x2, ref Vector128<uint> x3,
			ref Vector128<uint> o0, ref Vector128<uint> o1, ref Vector128<uint> o2, ref Vector128<uint> o3,
			byte* source, byte* destination)
		{
			// x+=o
			x0 = Sse2.Add(x0, o0);
			x1 = Sse2.Add(x1, o1);
			x2 = Sse2.Add(x2, o2);
			x3 = Sse2.Add(x3, o3);

			// Transpose
			var t0 = Sse2.UnpackLow(x0, x1);
			var t1 = Sse2.UnpackLow(x2, x3);
			var t2 = Sse2.UnpackHigh(x0, x1);
			var t3 = Sse2.UnpackHigh(x2, x3);

			x0 = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
			x1 = Sse2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
			x2 = Sse2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
			x3 = Sse2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();

			// Xor
			Sse2.Store(destination, Sse2.Xor(x0.AsByte(), Sse2.LoadVector128(source)));
			Sse2.Store(destination + 64, Sse2.Xor(x1.AsByte(), Sse2.LoadVector128(source + 64)));
			Sse2.Store(destination + 128, Sse2.Xor(x2.AsByte(), Sse2.LoadVector128(source + 128)));
			Sse2.Store(destination + 192, Sse2.Xor(x3.AsByte(), Sse2.LoadVector128(source + 192)));
		}

		#endregion

		#region 处理 512*n bytes

		private static readonly Vector256<ulong> IncCounter0123 = Vector256.Create(0ul, 1, 2, 3);
		private static readonly Vector256<ulong> IncCounter4567 = Vector256.Create(4ul, 5, 6, 7);
		private static readonly Vector256<uint> IncCounter01234567 = Vector256.Create(0u, 1, 2, 3, 4, 5, 6, 7);

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCoreOriginal512(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			var o0 = Vector256.Create(*(state + 0));
			var o1 = Vector256.Create(*(state + 1));
			var o2 = Vector256.Create(*(state + 2));
			var o3 = Vector256.Create(*(state + 3));
			var o4 = Vector256.Create(*(state + 4));
			var o5 = Vector256.Create(*(state + 5));
			var o6 = Vector256.Create(*(state + 6));
			var o7 = Vector256.Create(*(state + 7));
			var o8 = Vector256.Create(*(state + 8));
			var o9 = Vector256.Create(*(state + 9));
			var o10 = Vector256.Create(*(state + 10));
			var o11 = Vector256.Create(*(state + 11));
			var o14 = Vector256.Create(*(state + 14));
			var o15 = Vector256.Create(*(state + 15));

			while (length >= 512)
			{
				var x0 = o0;
				var x1 = o1;
				var x2 = o2;
				var x3 = o3;
				var x4 = o4;
				var x5 = o5;
				var x6 = o6;
				var x7 = o7;
				var x8 = o8;
				var x9 = o9;
				var x10 = o10;
				var x11 = o11;
				var x14 = o14;
				var x15 = o15;

				var counter = *(state + 12) | (ulong)*(state + 13) << 32;
				var x12 = Vector256.Create(counter).AsUInt32();
				var x13 = x12;

				var t0 = Avx2.Add(IncCounter0123, x12.AsUInt64()).AsUInt32();
				var t1 = Avx2.Add(IncCounter4567, x13.AsUInt64()).AsUInt32();

				x12 = Avx2.UnpackLow(t0, t1);
				x13 = Avx2.UnpackHigh(t0, t1);

				t0 = Avx2.UnpackLow(x12, x13);
				t1 = Avx2.UnpackHigh(x12, x13);

				x12 = Avx2.PermuteVar8x32(t0, Permute3);
				x13 = Avx2.PermuteVar8x32(t1, Permute3);

				var o12 = x12;
				var o13 = x13;

				counter += 8;

				*(state + 12) = (uint)(counter & 0xFFFFFFFF);
				*(state + 13) = (uint)(counter >> 32 & 0xFFFFFFFF);

				for (var i = 0; i < rounds; i += 2)
				{
					QuarterRound(ref x0, ref x4, ref x8, ref x12);
					QuarterRound(ref x1, ref x5, ref x9, ref x13);
					QuarterRound(ref x2, ref x6, ref x10, ref x14);
					QuarterRound(ref x3, ref x7, ref x11, ref x15);
					QuarterRound(ref x0, ref x5, ref x10, ref x15);
					QuarterRound(ref x1, ref x6, ref x11, ref x12);
					QuarterRound(ref x2, ref x7, ref x8, ref x13);
					QuarterRound(ref x3, ref x4, ref x9, ref x14);
				}

				AddTransposeXor(
					ref x0, ref x1, ref x2, ref x3,
					ref x4, ref x5, ref x6, ref x7,
					ref o0, ref o1, ref o2, ref o3,
					ref o4, ref o5, ref o6, ref o7,
					source, destination);
				AddTransposeXor(
					ref x8, ref x9, ref x10, ref x11,
					ref x12, ref x13, ref x14, ref x15,
					ref o8, ref o9, ref o10, ref o11,
					ref o12, ref o13, ref o14, ref o15,
					source + 32, destination + 32);

				length -= 512;
				destination += 512;
				source += 512;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void ChaChaCore512(byte rounds, uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			var o0 = Vector256.Create(*(state + 0));
			var o1 = Vector256.Create(*(state + 1));
			var o2 = Vector256.Create(*(state + 2));
			var o3 = Vector256.Create(*(state + 3));
			var o4 = Vector256.Create(*(state + 4));
			var o5 = Vector256.Create(*(state + 5));
			var o6 = Vector256.Create(*(state + 6));
			var o7 = Vector256.Create(*(state + 7));
			var o8 = Vector256.Create(*(state + 8));
			var o9 = Vector256.Create(*(state + 9));
			var o10 = Vector256.Create(*(state + 10));
			var o11 = Vector256.Create(*(state + 11));
			var o13 = Vector256.Create(*(state + 13));
			var o14 = Vector256.Create(*(state + 14));
			var o15 = Vector256.Create(*(state + 15));

			while (length >= 512)
			{
				var x0 = o0;
				var x1 = o1;
				var x2 = o2;
				var x3 = o3;
				var x4 = o4;
				var x5 = o5;
				var x6 = o6;
				var x7 = o7;
				var x8 = o8;
				var x9 = o9;
				var x10 = o10;
				var x11 = o11;
				var x13 = o13;
				var x14 = o14;
				var x15 = o15;

				var x12 = Avx2.Add(IncCounter01234567, Vector256.Create(*(state + 12)));
				var o12 = x12;

				*(state + 12) += 8;

				for (var i = 0; i < rounds; i += 2)
				{
					QuarterRound(ref x0, ref x4, ref x8, ref x12);
					QuarterRound(ref x1, ref x5, ref x9, ref x13);
					QuarterRound(ref x2, ref x6, ref x10, ref x14);
					QuarterRound(ref x3, ref x7, ref x11, ref x15);
					QuarterRound(ref x0, ref x5, ref x10, ref x15);
					QuarterRound(ref x1, ref x6, ref x11, ref x12);
					QuarterRound(ref x2, ref x7, ref x8, ref x13);
					QuarterRound(ref x3, ref x4, ref x9, ref x14);
				}

				AddTransposeXor(
					ref x0, ref x1, ref x2, ref x3,
					ref x4, ref x5, ref x6, ref x7,
					ref o0, ref o1, ref o2, ref o3,
					ref o4, ref o5, ref o6, ref o7,
					source, destination);
				AddTransposeXor(
					ref x8, ref x9, ref x10, ref x11,
					ref x12, ref x13, ref x14, ref x15,
					ref o8, ref o9, ref o10, ref o11,
					ref o12, ref o13, ref o14, ref o15,
					source + 32, destination + 32);

				length -= 512;
				destination += 512;
				source += 512;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static unsafe void AddTransposeXor(
			ref Vector256<uint> x0, ref Vector256<uint> x1, ref Vector256<uint> x2, ref Vector256<uint> x3,
			ref Vector256<uint> x4, ref Vector256<uint> x5, ref Vector256<uint> x6, ref Vector256<uint> x7,
			ref Vector256<uint> o0, ref Vector256<uint> o1, ref Vector256<uint> o2, ref Vector256<uint> o3,
			ref Vector256<uint> o4, ref Vector256<uint> o5, ref Vector256<uint> o6, ref Vector256<uint> o7,
			byte* source, byte* destination)
		{
			// x += o
			x0 = Avx2.Add(x0, o0);
			x1 = Avx2.Add(x1, o1);
			x2 = Avx2.Add(x2, o2);
			x3 = Avx2.Add(x3, o3);
			x4 = Avx2.Add(x4, o4);
			x5 = Avx2.Add(x5, o5);
			x6 = Avx2.Add(x6, o6);
			x7 = Avx2.Add(x7, o7);

			// Transpose
			var t0 = Avx2.UnpackLow(x0, x1);
			var t1 = Avx2.UnpackLow(x2, x3);
			var t2 = Avx2.UnpackHigh(x0, x1);
			var t3 = Avx2.UnpackHigh(x2, x3);
			var t4 = Avx2.UnpackLow(x4, x5);
			var t5 = Avx2.UnpackLow(x6, x7);
			var t6 = Avx2.UnpackHigh(x4, x5);
			var t7 = Avx2.UnpackHigh(x6, x7);

			x0 = Avx2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
			x1 = Avx2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
			x2 = Avx2.UnpackLow(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
			x3 = Avx2.UnpackHigh(t2.AsUInt64(), t3.AsUInt64()).AsUInt32();
			x4 = Avx2.UnpackLow(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
			x5 = Avx2.UnpackHigh(t4.AsUInt64(), t5.AsUInt64()).AsUInt32();
			x6 = Avx2.UnpackLow(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();
			x7 = Avx2.UnpackHigh(t6.AsUInt64(), t7.AsUInt64()).AsUInt32();

			t0 = Avx2.Permute2x128(x0, x4, 0x20);
			t4 = Avx2.Permute2x128(x0, x4, 0x31);
			t1 = Avx2.Permute2x128(x1, x5, 0x20);
			t5 = Avx2.Permute2x128(x1, x5, 0x31);
			t2 = Avx2.Permute2x128(x2, x6, 0x20);
			t6 = Avx2.Permute2x128(x2, x6, 0x31);
			t3 = Avx2.Permute2x128(x3, x7, 0x20);
			t7 = Avx2.Permute2x128(x3, x7, 0x31);

			// Xor
			Avx.Store(destination, Avx2.Xor(t0.AsByte(), Avx.LoadVector256(source)));
			Avx.Store(destination + 64, Avx2.Xor(t1.AsByte(), Avx.LoadVector256(source + 64)));
			Avx.Store(destination + 128, Avx2.Xor(t2.AsByte(), Avx.LoadVector256(source + 128)));
			Avx.Store(destination + 192, Avx2.Xor(t3.AsByte(), Avx.LoadVector256(source + 192)));
			Avx.Store(destination + 256, Avx2.Xor(t4.AsByte(), Avx.LoadVector256(source + 256)));
			Avx.Store(destination + 320, Avx2.Xor(t5.AsByte(), Avx.LoadVector256(source + 320)));
			Avx.Store(destination + 384, Avx2.Xor(t6.AsByte(), Avx.LoadVector256(source + 384)));
			Avx.Store(destination + 448, Avx2.Xor(t7.AsByte(), Avx.LoadVector256(source + 448)));
		}

		#endregion

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
