namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public abstract class ChaCha20OriginalCrypto : ChaCha20CryptoBase
	{
		public override string Name => @"ChaCha20Original";

		protected ChaCha20OriginalCrypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void IncrementCounter(uint* state)
		{
			ChaCha20Utils.IncrementCounterOriginal(state);
		}

		protected override unsafe void SnuffleCore64(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCoreOriginal64(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore128(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCoreOriginal128(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore256(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			ChaCha20Utils.ChaChaCoreOriginal256(Rounds, state, ref source, ref destination, ref length);
		}

		protected override unsafe void SnuffleCore512(uint* state, ref byte* source, ref byte* destination, ref int length)
		{
			ChaCha20Utils.ChaChaCoreOriginal512(Rounds, state, ref source, ref destination, ref length);
		}
	}
}
