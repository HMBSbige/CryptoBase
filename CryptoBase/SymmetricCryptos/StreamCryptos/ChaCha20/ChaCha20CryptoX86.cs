using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20
{
	public class ChaCha20CryptoX86 : ChaCha20CryptoSF
	{
		public override bool IsSupport => Sse2.IsSupported;

		public ChaCha20CryptoX86(byte[] key, byte[] iv) : base(key, iv) { }

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
