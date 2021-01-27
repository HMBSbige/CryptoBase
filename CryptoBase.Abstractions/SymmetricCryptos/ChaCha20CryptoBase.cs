namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class ChaCha20CryptoBase : SnuffleCryptoBase
	{
		public override string Name { get; } = @"ChaCha20";

		protected ChaCha20CryptoBase(byte[] key, byte[] iv) : base(key, iv) { }
	}
}
