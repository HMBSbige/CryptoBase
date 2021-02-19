namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20
{
	public class XSalsa20CryptoSF : XSalsa20CryptoX86
	{
		public override bool IsSupport => false;

		public XSalsa20CryptoSF(byte[] key, byte[] iv) : base(key, iv) { }

		protected override void SalsaRound(uint[] x)
		{
			Salsa20Utils.SalsaRound(Rounds, x);
		}
	}
}
