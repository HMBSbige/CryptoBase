namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original
{
	public abstract class ChaCha20OriginalCrypto : SnuffleCrypto
	{
		public override string Name => @"ChaCha20Original";

		protected ChaCha20OriginalCrypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void SnuffleCore64(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore64(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore128(uint* state, byte* source, byte* destination)
		{
			ChaCha20Utils.ChaChaCore128(Rounds, state, source, destination);
		}

		protected override unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 12) == 0)
			{
				++*(state + 13);
			}
		}
	}
}
