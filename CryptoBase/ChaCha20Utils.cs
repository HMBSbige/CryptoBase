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
				UpdateKeyStream(rounds, state, x);
				var span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, 64));
				x.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(span);
			}
			finally
			{
				ArrayPool<uint>.Shared.Return(x);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void UpdateKeyStream(int rounds, uint[] state, uint[] x)
		{
			state.AsSpan().CopyTo(x);

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

			for (var i = 0; i < SnuffleCryptoBase.StateSize; i += 4)
			{
				x[i] += state[i];
				x[i + 1] += state[i + 1];
				x[i + 2] += state[i + 2];
				x[i + 3] += state[i + 3];
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
	}
}
