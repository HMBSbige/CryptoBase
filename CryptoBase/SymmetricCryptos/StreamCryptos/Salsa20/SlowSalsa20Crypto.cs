namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class SlowSalsa20Crypto : FastSalsa20Crypto
	{
		public SlowSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			Salsa20Utils.SalsaCore(Rounds, state, keyStream);
		}
	}
}
