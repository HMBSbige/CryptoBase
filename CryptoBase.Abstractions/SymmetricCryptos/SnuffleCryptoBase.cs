namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class SnuffleCryptoBase : StreamCryptoBase
	{
		public const int StateSize = 16; // 64 bytes

		public abstract int IvSize { get; }

		protected SnuffleCryptoBase(byte[] key, byte[] iv) { }
	}
}
