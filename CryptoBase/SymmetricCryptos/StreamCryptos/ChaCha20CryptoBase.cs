namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class ChaCha20CryptoBase : SnuffleCrypto
	{
		protected ChaCha20CryptoBase(byte[] key, byte[] iv) : base(key, iv) { }
	}
}
