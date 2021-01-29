using System;
using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20
{
	public class SlowXChaCha20Crypto : XChaCha20Crypto
	{
		public override bool IsSupport => false;

		public SlowXChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Init();
			Reset();
		}

		private void Init()
		{
			if (Key.Length != 32)
			{
				throw new ArgumentException(@"Key length requires 32 bytes");
			}

			var span = State.AsSpan();
			var sigma = Sigma32.AsSpan();

			sigma.CopyTo(span);

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			keySpan.CopyTo(span.Slice(4));

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			ivSpan.Slice(0, 4).CopyTo(span.Slice(12));

			ChaChaRound(State);

			span.Slice(12).CopyTo(span.Slice(8));
			span.Slice(0, 4).CopyTo(span.Slice(4));

			sigma.CopyTo(span);

			State[12] = 1;
			State[13] = 0;
			State[14] = ivSpan[4];
			State[15] = ivSpan[5];
		}

		public sealed override void Reset()
		{
			Index = 0;
			State[12] = State[13] = 0;
		}

		protected override void UpdateKeyStream()
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected virtual void ChaChaRound(uint[] x)
		{
			ChaCha20Utils.ChaChaRound(Rounds, x);
		}
	}
}
