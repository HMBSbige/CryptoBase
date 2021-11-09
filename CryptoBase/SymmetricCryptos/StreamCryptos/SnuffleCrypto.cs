using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class SnuffleCrypto : SnuffleCryptoBase
	{
		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected static readonly uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected static readonly uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

		protected byte Rounds { get; init; } = 20;

		protected readonly uint[] State;
		protected readonly byte[] KeyStream;

		protected int Index;

		protected SnuffleCrypto()
		{
			State = ArrayPool<uint>.Shared.Rent(StateSize);
			KeyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));
		}

		public override unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Update(source, destination);

			var length = source.Length;
			fixed (uint* pState = State)
			fixed (byte* pStream = KeyStream)
			fixed (byte* pSource = source)
			fixed (byte* pDestination = destination)
			{
				Update(length, pState, pStream, pSource, pDestination);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private unsafe void Update(int length, uint* state, byte* stream, byte* source, byte* destination)
		{
			while (length > 0)
			{
				if (Index == 0)
				{
					UpdateBlocks(ref state, ref source, ref destination, ref length);

					if (length == 0)
					{
						break;
					}

					UpdateKeyStream();
					IncrementCounter(state);
				}

				var r = 64 - Index;
				Xor(stream + Index, source, destination, Math.Min(r, length));

				if (length < r)
				{
					Index += length;
					return;
				}

				Index = 0;
				length -= r;
				source += r;
				destination += r;
			}
		}

		protected abstract unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length);
		protected abstract void UpdateKeyStream();
		protected abstract unsafe void IncrementCounter(uint* state);
		protected abstract unsafe void Xor(byte* stream, byte* source, byte* destination, int length);

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(State);
			ArrayPool<byte>.Shared.Return(KeyStream);
		}
	}
}
