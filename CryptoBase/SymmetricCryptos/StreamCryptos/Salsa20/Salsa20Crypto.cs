using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public abstract class Salsa20Crypto : Salsa20CryptoBase, IIntrinsics
	{
		public abstract bool IsSupport { get; }

		protected readonly uint[] State;
		protected readonly byte[] KeyStream;

		protected readonly ReadOnlyMemory<byte> Key;
		protected readonly ReadOnlyMemory<byte> Iv;

		protected byte Rounds { get; init; } = 20;

		protected int Index;

		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected readonly static uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected readonly static uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Key = key;
			Iv = iv;

			State = ArrayPool<uint>.Shared.Rent(StateSize);
			KeyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		protected override unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			var length = source.Length;
			fixed (uint* pState = State)
			fixed (byte* pStream = KeyStream)
			fixed (byte* pSource = source)
			fixed (byte* pDestination = destination)
			{
				Update(length, pState, pStream, pSource, pDestination);
			}
		}

		private unsafe void Update(int length, uint* state, byte* stream, byte* source, byte* destination)
		{
			while (length > 0)
			{
				if (Index == 0)
				{
					if (IsSupport)
					{
						while (length > 64)
						{
							Salsa20Utils.SalsaCore64(Rounds, state, source, destination);

							source += 64;
							destination += 64;
							length -= 64;
						}
					}
					if (length == 0)
					{
						break;
					}
					UpdateKeyStream(State, KeyStream);
				}

				var r = 64 - Index;

				IntrinsicsUtils.Xor(stream + Index, source, destination, Math.Min(r, length));

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

		private unsafe void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			if (IsSupport)
			{
				fixed (uint* x = state)
				fixed (byte* s = keyStream)
				{
					Salsa20Utils.UpdateKeyStream(x, s, Rounds);
					if (++*(x + 8) == 0)
					{
						++*(x + 9);
					}
				}
			}
			else
			{
				Salsa20Utils.UpdateKeyStream(Rounds, state, keyStream);
				if (++state[8] == 0)
				{
					++state[9];
				}
			}
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(State);
			ArrayPool<byte>.Shared.Return(KeyStream);
		}
	}
}
