using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public class ChaCha20OriginalCryptoSF : ChaCha20OriginalCrypto
	{
		public ChaCha20OriginalCryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

		protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length) { }

		protected override void UpdateKeyStream()
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
		{
			IntrinsicsUtils.XorSoftwareFallback(stream, source, destination, length);
		}
	}
}
