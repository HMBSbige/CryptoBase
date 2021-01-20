namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class ChachaCryptoBase : StreamCryptoBase
	{
		public abstract int IvSize { get; }
	}
}
