using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20
{
	public class XChaCha20CryptoSF : XChaCha20Crypto
	{
		public XChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

		protected override void ChaChaRound(uint[] x)
		{
			ChaCha20Utils.ChaChaRound(Rounds, x);
		}

		protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length) { }

		protected override void UpdateKeyStream()
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
		{
			FastUtils.Xor(stream, source, destination, length);
		}
	}
}
