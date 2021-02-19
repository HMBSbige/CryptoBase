using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class Salsa20Crypto : SnuffleCrypto
	{
		public override string Name => @"Salsa20";

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
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

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private unsafe void Update(int length, uint* state, byte* stream, byte* source, byte* destination)
		{
			while (length > 0)
			{
				if (Index == 0)
				{
					if (IsSupport)
					{
						if (Avx.IsSupported && Avx2.IsSupported)
						{
							while (length >= 128)
							{
								Salsa20Utils.SalsaCore128(Rounds, state, source, destination);

								source += 128;
								destination += 128;
								length -= 128;
							}
						}

						if (Sse2.IsSupported)
						{
							if (length >= 256)
							{
								Salsa20Utils.SalsaCore256(Rounds, state, ref source, ref destination, ref length);
							}

							while (length >= 64)
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
					}

					UpdateKeyStream();
					IncrementCounter(state);
				}

				var r = 64 - Index;

				if (IsSupport)
				{
					IntrinsicsUtils.Xor(stream + Index, source, destination, Math.Min(r, length));
				}
				else
				{
					IntrinsicsUtils.XorSoftwareFallback(stream + Index, source, destination, Math.Min(r, length));
				}

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

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private unsafe void UpdateKeyStream()
		{
			if (IsSupport)
			{
				if (Sse2.IsSupported)
				{
					fixed (uint* x = State)
					fixed (byte* s = KeyStream)
					{
						Salsa20Utils.UpdateKeyStream(x, s, Rounds);
					}
					return;
				}
			}

			Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}
	}
}
