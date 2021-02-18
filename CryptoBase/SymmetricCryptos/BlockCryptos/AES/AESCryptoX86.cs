namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public abstract class AESCryptoX86 : AESCrypto
	{
		public override bool IsSupport => AESUtils.IsSupportX86;

		protected AESCryptoX86(byte[] key) : base(key) { }
	}
}
