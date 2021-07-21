using System;
using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20
{
	public abstract class XChaCha20Crypto : ChaCha20CryptoBase
	{
		public override string Name => @"XChaCha20";

		public override int IvSize => 24;

		private readonly ReadOnlyMemory<byte> Key;

		protected XChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv)
		{
			if (key.Length != 32)
			{
				throw new ArgumentException(@"Key length requires 32 bytes");
			}

			Key = key.ToArray();

			SetIV(iv);
			Reset();
		}

		public sealed override void Reset()
		{
			SetCounter(0);
		}

		protected override unsafe void IncrementCounter(uint* state)
		{
			ChaCha20Utils.IncrementCounterOriginal(state);
		}

		protected abstract void ChaChaRound(uint[] x);

		public void SetIV(ReadOnlySpan<byte> iv)
		{
			var span = State.AsSpan();
			var sigma = Sigma32.AsSpan();

			sigma.CopyTo(span);

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			keySpan.CopyTo(span[4..]);

			var ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
			ivSpan[..4].CopyTo(span[12..]);

			ChaChaRound(State);

			span[12..].CopyTo(span[8..]);
			span[..4].CopyTo(span[4..]);

			sigma.CopyTo(span);

			State[14] = ivSpan[4];
			State[15] = ivSpan[5];
		}

		public void SetCounter(uint counter)
		{
			Index = 0;
			State[12] = counter;
			State[13] = 0;
		}
	}
}
