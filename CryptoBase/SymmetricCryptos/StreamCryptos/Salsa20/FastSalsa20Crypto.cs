using CryptoBase.Abstractions;
using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class FastSalsa20Crypto : Salsa20Crypto, IIntrinsics
	{
		public bool IsSupport => Sse2.IsSupported;

		public FastSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Reset();
		}

		protected override unsafe void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			fixed (uint* x = state)
			fixed (byte* s = keyStream)
			{
				Salsa20Utils.SalsaCore(x, s, Rounds);
				if (++*(x + 8) == 0)
				{
					++*(x + 9);
				}
			}
		}

		public sealed override void Reset()
		{
			var keyLength = Key.Length;
			switch (keyLength)
			{
				case 16:
				{
					State[0] = Sigma16[0];
					State[5] = Sigma16[1];
					State[10] = Sigma16[2];
					State[15] = Sigma16[3];
					break;
				}
				case 32:
				{
					State[0] = Sigma32[0];
					State[5] = Sigma32[1];
					State[10] = Sigma32[2];
					State[15] = Sigma32[3];
					break;
				}
				default:
				{
					throw new ArgumentException(@"Key length requires 16 or 32 bytes");
				}
			}

			var key = MemoryMarshal.Cast<byte, uint>(Key.Span);
			State[1] = key[0];
			State[2] = key[1];
			State[3] = key[2];
			State[4] = key[3];

			if (keyLength == 32)
			{
				State[11] = key[4];
				State[12] = key[5];
				State[13] = key[6];
				State[14] = key[7];
			}
			else
			{
				State[11] = key[0];
				State[12] = key[1];
				State[13] = key[2];
				State[14] = key[3];
			}

			var iv = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			State[6] = iv[0];
			State[7] = iv[1];

			Index = 0;
			State[8] = State[9] = 0;
		}
	}
}
