namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class Salsa20CryptoBase : SnuffleCryptoBase
	{
		public override string Name { get; } = @"Salsa20";

		protected Salsa20CryptoBase(byte[] key, byte[] iv) : base(key, iv) { }
	}
}
