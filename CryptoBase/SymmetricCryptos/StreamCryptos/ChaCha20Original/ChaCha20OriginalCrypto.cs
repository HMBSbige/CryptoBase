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

		protected override unsafe void ChaChaCore64(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCoreOriginal64(Rounds, state, source, destination);
		}

		protected override unsafe void ChaChaCore128(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCoreOriginal128(Rounds, state, source, destination);
		}
	}
}
