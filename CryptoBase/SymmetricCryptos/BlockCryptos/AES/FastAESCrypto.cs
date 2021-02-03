namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public abstract class FastAESCrypto : AESCrypto
	{
		public override bool IsSupport => AESUtils.IsSupportX86;

		protected FastAESCrypto(byte[] key) : base(key) { }
	}
}
