using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

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

				for (var i = 0; i < SnuffleCryptoBase.StateSize; ++i)
				{
					x[i] += state[i];
				}
			}
			finally
			{
				ArrayPool<uint>.Shared.Return(x);
			}

			var span = keyStream.AsSpan();
			for (var j = 0; j < SnuffleCryptoBase.StateSize; j++)
			{
				BinaryPrimitives.WriteUInt32LittleEndian(span, x[j]);
				span = span.Slice(4);
			}

			if (++state[8] == 0)
			{
				++state[9];
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void SalsaQuarterRound(uint[] x, int a, int b, int c, int d)
		{
			SalsaStep(ref x[a], x[b], x[c], 7);
			SalsaStep(ref x[d], x[a], x[b], 9);
			SalsaStep(ref x[c], x[d], x[a], 13);
			SalsaStep(ref x[b], x[c], x[d], 18);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void SalsaStep(ref uint a, uint b, uint c, byte i)
		{
			a ^= (b + c).RotateLeft(i);
		}
	}
}
