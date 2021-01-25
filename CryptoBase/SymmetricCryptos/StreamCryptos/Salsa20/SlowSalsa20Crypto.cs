namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public class SlowSalsa20Crypto : FastSalsa20Crypto
	{
		public override bool IsSupport { get; } = false;
		public SlowSalsa20Crypto(byte[] key, byte[] iv) : base(key, iv) { }
	}
}
