using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class Salsa20CryptoX86 : Salsa20Crypto
	{
		public override bool IsSupport => Sse2.IsSupported;

		public Salsa20CryptoX86(byte[] key, byte[] iv) : base(key, iv)
		{
			Init();
			Reset();
		}

		private void Init()
		{
			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			var keyLength = Key.Length;
			switch (keyLength)
			{
				case 16:
				{
					State[0] = Sigma16[0];
					State[5] = Sigma16[1];
					State[10] = Sigma16[2];
					State[15] = Sigma16[3];
					State[11] = keySpan[0];
					State[12] = keySpan[1];
					State[13] = keySpan[2];
					State[14] = keySpan[3];
					break;
				}
				case 32:
				{
					State[0] = Sigma32[0];
					State[5] = Sigma32[1];
					State[10] = Sigma32[2];
					State[15] = Sigma32[3];
					State[11] = keySpan[4];
					State[12] = keySpan[5];
					State[13] = keySpan[6];
					State[14] = keySpan[7];
					break;
				}
				default:
				{
					throw new ArgumentException(@"Key length requires 16 or 32 bytes");
				}
			}

			State[1] = keySpan[0];
			State[2] = keySpan[1];
			State[3] = keySpan[2];
			State[4] = keySpan[3];

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			State[6] = ivSpan[0];
			State[7] = ivSpan[1];
		}

		protected override unsafe void UpdateKeyStream()
		{
			fixed (uint* x = State)
			fixed (byte* s = KeyStream)
			{
				Salsa20Utils.UpdateKeyStream(x, s, Rounds);
			}
		}

		public sealed override void Reset()
		{
			Index = 0;
			State[8] = State[9] = 0;
		}
	}
}
