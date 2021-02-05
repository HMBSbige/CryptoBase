using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20
{
	public class FastChaCha20Crypto : SlowChaCha20Crypto
	{
		public override bool IsSupport => Sse2.IsSupported && Ssse3.IsSupported;

		public FastChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void UpdateKeyStream()
		{
			fixed (uint* x = State)
			fixed (byte* s = KeyStream)
			{
				ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
			}
		}
	}
}
