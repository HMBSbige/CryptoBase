using System;
using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20
{
	public class SlowChaCha20Crypto : ChaCha20Crypto
	{
		public override bool IsSupport => false;

		public SlowChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv)
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

			State[0] = Sigma32[0];
			State[1] = Sigma32[1];
			State[2] = Sigma32[2];
			State[3] = Sigma32[3];

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			keySpan.CopyTo(State.AsSpan(4));

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			State[13] = ivSpan[0];
			State[14] = ivSpan[1];
			State[15] = ivSpan[2];
		}

		public sealed override void Reset()
		{
			Index = 0;
			State[12] = 0;
		}

		protected override void UpdateKeyStream()
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}
	}
}
