using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class XSalsa20CryptoX86 : Salsa20Crypto
	{
		public override bool IsSupport => Sse2.IsSupported;

		public override string Name => @"XSalsa20";

		public override int IvSize => 24;

		public XSalsa20CryptoX86(byte[] key, byte[] iv) : base(key, iv)
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

			State[0] = Sigma32[0];
			State[5] = Sigma32[1];
			State[10] = Sigma32[2];
			State[15] = Sigma32[3];

			var keySpan = MemoryMarshal.Cast<byte, uint>(Key.Span);
			keySpan.Slice(0, 4).CopyTo(span.Slice(1));
			keySpan.Slice(4).CopyTo(span.Slice(11));

			var ivSpan = MemoryMarshal.Cast<byte, uint>(Iv.Span);
			ivSpan.Slice(0, 4).CopyTo(span.Slice(6));

			SalsaRound(State);

			State[1] = State[0];
			State[2] = State[5];
			State[3] = State[10];
			State[4] = State[15];

			span.Slice(6, 4).CopyTo(span.Slice(11));

			State[6] = ivSpan[4];
			State[7] = ivSpan[5];

			State[8] = ivSpan[2];
			State[9] = ivSpan[3];

			State[0] = Sigma32[0];
			State[5] = Sigma32[1];
			State[10] = Sigma32[2];
			State[15] = Sigma32[3];
		}

		public sealed override void Reset()
		{
			Index = 0;
			State[8] = State[9] = 0;
		}

		protected virtual unsafe void SalsaRound(uint[] x)
		{
			fixed (uint* p = x)
			{
				Salsa20Utils.SalsaRound(p, Rounds);
			}
		}
	}
}
