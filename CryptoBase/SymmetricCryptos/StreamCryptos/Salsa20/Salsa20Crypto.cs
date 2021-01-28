namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public abstract class Salsa20Crypto : SnuffleCrypto
	{
		public override string Name => @"Salsa20";

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void SnuffleCore64(uint* state, byte* source, byte* destination)
		{
			Salsa20Utils.SalsaCore64(Rounds, state, source, destination);
		}

		protected override unsafe void SnuffleCore128(uint* state, byte* source, byte* destination)
		{
			Salsa20Utils.SalsaCore128(Rounds, state, source, destination);
		}

		protected override unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}
	}
}
