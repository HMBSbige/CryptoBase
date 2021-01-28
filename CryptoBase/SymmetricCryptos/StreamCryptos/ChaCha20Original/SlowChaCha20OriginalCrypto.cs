using System;
using System.Runtime.InteropServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public class SlowChaCha20OriginalCrypto : ChaCha20OriginalCrypto
	{
		public override bool IsSupport => false;

		public SlowChaCha20OriginalCrypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Init();
			Reset();
		}

		private void Init()
		{
			var keyLength = Key.Length;
			switch (keyLength)
			{
				case 16:
				{
					State[0] = Sigma16[0];
					State[1] = Sigma16[1];
					State[2] = Sigma16[2];
					State[3] = Sigma16[3];
					break;
				}
				case 32:
				{
					State[0] = Sigma32[0];
					State[1] = Sigma32[1];
					State[2] = Sigma32[2];
					State[3] = Sigma32[3];
					break;
				}
				default:
				{
					throw new ArgumentException(@"Key length requires 16 or 32 bytes");
				}
			}

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			State[4] = keySpan[0];
			State[5] = keySpan[1];
			State[6] = keySpan[2];
			State[7] = keySpan[3];

			if (keyLength == 32)
			{
				State[8] = keySpan[4];
				State[9] = keySpan[5];
				State[10] = keySpan[6];
				State[11] = keySpan[7];
			}
			else
			{
				State[8] = keySpan[0];
				State[9] = keySpan[1];
				State[10] = keySpan[2];
				State[11] = keySpan[3];
			}

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			State[14] = ivSpan[0];
			State[15] = ivSpan[1];
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
	}
}
