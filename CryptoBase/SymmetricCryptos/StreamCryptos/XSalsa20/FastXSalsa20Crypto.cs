using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class FastXSalsa20Crypto : Salsa20Crypto
	{
		public override bool IsSupport => Sse2.IsSupported;

		public override string Name => @"XSalsa20";

		public override int IvSize => 24;

		public FastXSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
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
			State[5] = Sigma32[1];
			State[10] = Sigma32[2];
			State[15] = Sigma32[3];

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			State[1] = keySpan[0];
			State[2] = keySpan[1];
			State[3] = keySpan[2];
			State[4] = keySpan[3];

			State[11] = keySpan[4];
			State[12] = keySpan[5];
			State[13] = keySpan[6];
			State[14] = keySpan[7];

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			State[6] = ivSpan[0];
			State[7] = ivSpan[1];
			State[8] = ivSpan[2];
			State[9] = ivSpan[3];

			UpdateKeyStream();

			var stream = MemoryMarshal.Cast<byte, uint>(KeyStream.AsSpan(0, 64));

			State[1] = stream[0] - State[0];
			State[2] = stream[5] - State[5];
			State[3] = stream[10] - State[10];
			State[4] = stream[15] - State[15];

			State[11] = stream[6] - State[6];
			State[12] = stream[7] - State[7];
			State[13] = stream[8] - State[8];
			State[14] = stream[9] - State[9];

			State[6] = ivSpan[4];
			State[7] = ivSpan[5];
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
