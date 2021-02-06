using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public class FastChaCha20OriginalCrypto : SlowChaCha20OriginalCrypto
	{
		public override bool IsSupport => Sse2.IsSupported;

		public FastChaCha20OriginalCrypto(byte[] key, byte[] iv) : base(key, iv) { }

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
