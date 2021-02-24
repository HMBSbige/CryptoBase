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

		protected override unsafe void SnuffleCore64(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore64(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore128(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore128(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore256(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			ChaCha20Utils.ChaChaCore256(Rounds, state, ref source, ref destination, ref length);
		}

		protected override unsafe void SnuffleCore512(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			ChaCha20Utils.ChaChaCore512(Rounds, state, ref source, ref destination, ref length);
		}

		public abstract void SetIV(ReadOnlySpan<byte> iv);
		public abstract void SetCounter(uint counter);
	}
}
