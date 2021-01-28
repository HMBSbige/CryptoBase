using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
				QuarterRound(x, 0, 4, 8, 12);
				QuarterRound(x, 1, 5, 9, 13);
				QuarterRound(x, 2, 6, 10, 14);
				QuarterRound(x, 3, 7, 11, 15);

				QuarterRound(x, 0, 5, 10, 15);
				QuarterRound(x, 1, 6, 11, 12);
				QuarterRound(x, 2, 7, 8, 13);
				QuarterRound(x, 3, 4, 9, 14);
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
		private static void QuarterRound(uint[] x, int a, int b, int c, int d)
		{
			Step(ref x[a], x[b], ref x[d], 16);
			Step(ref x[c], x[d], ref x[b], 12);
			Step(ref x[a], x[b], ref x[d], 8);
			Step(ref x[c], x[d], ref x[b], 7);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void Step(ref uint a, uint b, ref uint c, byte i)
		{
			a += b;
			c = (a ^ c).RotateLeft(i);
		}
	}
}
