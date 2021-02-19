using System;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20
{
	public abstract class ChaCha20Crypto : ChaCha20CryptoBase
	{
		public override string Name => @"ChaCha20";

		public override int IvSize => 12;

		protected ChaCha20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void IncrementCounter(uint* state)
		{
			ChaCha20Utils.IncrementCounter(state);
		}

		protected override unsafe void ChaChaCore64(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore64(Rounds, state, source, destination);
		}

		protected override unsafe void ChaChaCore128(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore128(Rounds, state, source, destination);
		}

		public abstract void SetIV(ReadOnlySpan<byte> iv);
		public abstract void SetCounter(uint counter);
	}
}
