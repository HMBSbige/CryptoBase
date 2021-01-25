namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class SlowXSalsa20Crypto : FastXSalsa20Crypto
	{
		public override bool IsSupport { get; } = false;

		public SlowXSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }

		protected override void UpdateKeyStream()
		{
			Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}
	}
}
