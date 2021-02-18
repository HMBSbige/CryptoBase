using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public class ChaCha20OriginalCryptoX86 : ChaCha20OriginalCryptoSF
	{
		public override bool IsSupport => Sse2.IsSupported;

		public ChaCha20OriginalCryptoX86(byte[] key, byte[] iv) : base(key, iv) { }

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
