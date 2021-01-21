namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class SlowSalsa20Crypto : IntrinsicsSalsa20Crypto
	{
		public SlowSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override void UpdateKeyStream(uint[] state, byte[] keyStream)
		{
			ChaCha20Utils.SalsaCore(Rounds, state, keyStream);
		}
	}
}
