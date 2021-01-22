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
		public static void SalsaCore(int rounds, uint[] state, byte[] keyStream)
		{
			var x = ArrayPool<uint>.Shared.Rent(SnuffleCryptoBase.StateSize);
			try
			{
				SalsaCore(rounds, state, x);
			}
			finally
			{
				ArrayPool<uint>.Shared.Return(x);
			}

			var span = MemoryMarshal.Cast<byte, uint>(keyStream.AsSpan(0, 64));
			x.AsSpan(0, SnuffleCryptoBase.StateSize).CopyTo(span);

			if (++state[8] == 0)
			{
				++state[9];
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void SalsaCore(int rounds, uint[] state, uint[] x)
		{
			state.AsSpan().CopyTo(x);
			for (var i = 0; i < rounds; i += 2)
			{
				SalsaQuarterRound(x, 4, 0, 12, 8);
				SalsaQuarterRound(x, 9, 5, 1, 13);
				SalsaQuarterRound(x, 14, 10, 6, 2);
				SalsaQuarterRound(x, 3, 15, 11, 7);

				SalsaQuarterRound(x, 1, 0, 3, 2);
				SalsaQuarterRound(x, 6, 5, 4, 7);
				SalsaQuarterRound(x, 11, 10, 9, 8);
				SalsaQuarterRound(x, 12, 15, 14, 13);
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
		private static void SalsaQuarterRound(uint[] x, int a, int b, int c, int d)
		{
			SalsaStep(ref x[a], x[b], x[c], 7);
			SalsaStep(ref x[d], x[a], x[b], 9);
			SalsaStep(ref x[c], x[d], x[a], 13);
			SalsaStep(ref x[b], x[c], x[d], 18);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static void SalsaStep(ref uint a, uint b, uint c, byte i)
		{
			a ^= (b + c).RotateLeft(i);
		}
	}
}
