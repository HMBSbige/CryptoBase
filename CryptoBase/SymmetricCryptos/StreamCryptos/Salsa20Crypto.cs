namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class Salsa20Crypto : SnuffleCrypto
	{
		public override string Name => @"Salsa20";

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override unsafe void IncrementCounter(uint* state)
		{
			if (++*(state + 8) == 0)
			{
				++*(state + 9);
			}
		}
	}
}
