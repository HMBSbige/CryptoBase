using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20
{
	public class FastXChaCha20Crypto : SlowXChaCha20Crypto
	{
		public override bool IsSupport => Sse2.IsSupported && Ssse3.IsSupported;

		public FastXChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void UpdateKeyStream()
		{
			fixed (uint* x = State)
			fixed (byte* s = KeyStream)
			{
				ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
			}
		}

		protected override unsafe void ChaChaRound(uint[] x)
		{
			fixed (uint* p = x)
			{
				ChaCha20Utils.ChaChaRound(p, Rounds);
			}
		}
	}
}
