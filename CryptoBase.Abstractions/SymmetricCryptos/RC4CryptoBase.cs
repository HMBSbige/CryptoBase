namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class RC4CryptoBase : StreamCryptoBase
	{
		public override string Name => @"RC4";

		protected RC4CryptoBase(byte[] key) { }
	}
}
