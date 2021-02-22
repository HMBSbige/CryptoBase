using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class ChaCha20CryptoBase : SnuffleCrypto
	{
		protected ChaCha20CryptoBase(byte[] key, byte[] iv) : base(key, iv) { }

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
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
					if (IsSupport)
					{
						if (Avx.IsSupported && Avx2.IsSupported)
						{
							if (length >= 512)
							{
								ChaChaCore512(state, ref source, ref destination, ref length);
							}

							while (length >= 128)
							{
								ChaChaCore128(state, source, destination);

								source += 128;
								destination += 128;
								length -= 128;
							}
						}

						if (Sse2.IsSupported)
						{
							if (length >= 256)
							{
								ChaChaCore256(state, ref source, ref destination, ref length);
							}

							while (length >= 64)
							{
								ChaChaCore64(state, source, destination);

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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private unsafe void UpdateKeyStream()
		{
			if (IsSupport)
			{
				if (Sse2.IsSupported)
				{
					fixed (uint* x = State)
					fixed (byte* s = KeyStream)
					{
						ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
					}
					return;
				}
			}

			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected abstract unsafe void ChaChaCore64(uint* state, byte* source, byte* destination);
		protected abstract unsafe void ChaChaCore128(uint* state, byte* source, byte* destination);
		protected abstract unsafe void ChaChaCore256(uint* state, ref byte* source, ref byte* destination, ref int length);
		protected abstract unsafe void ChaChaCore512(uint* state, ref byte* source, ref byte* destination, ref int length);

		protected abstract unsafe void IncrementCounter(uint* state);
	}
}
