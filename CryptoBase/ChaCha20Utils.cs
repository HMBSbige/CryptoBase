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
	}
}
