namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class SnuffleCryptoBase : StreamCryptoBase
	{
		public const int StateSize = 16; // 64 bytes

		public virtual int IvSize => 8;

		protected SnuffleCryptoBase(byte[] key, byte[] iv) { }
	}
}
