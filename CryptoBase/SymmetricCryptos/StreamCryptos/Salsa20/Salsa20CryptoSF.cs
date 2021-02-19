namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class Salsa20CryptoSF : Salsa20CryptoX86
	{
		public override bool IsSupport => false;

		public Salsa20CryptoSF(byte[] key, byte[] iv) : base(key, iv) { }
	}
}
