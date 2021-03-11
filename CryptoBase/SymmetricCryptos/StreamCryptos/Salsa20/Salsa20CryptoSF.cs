using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class Salsa20CryptoSF : Salsa20CryptoX86
	{
		public Salsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

		protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length) { }

		protected override void UpdateKeyStream()
		{
			Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}

		protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
		{
			IntrinsicsUtils.XorSoftwareFallback(stream, source, destination, length);
		}
	}
}
