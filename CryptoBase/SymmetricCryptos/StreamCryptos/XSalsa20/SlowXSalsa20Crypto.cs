namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class SlowXSalsa20Crypto : FastXSalsa20Crypto
	{
		public SlowXSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			Salsa20Utils.SalsaCore(Rounds, state, keyStream);
		}
	}
}
