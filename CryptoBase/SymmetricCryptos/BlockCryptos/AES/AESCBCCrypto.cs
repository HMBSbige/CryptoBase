using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public sealed class AESCBCCrypto : NormalAESCrypto
	{
		public override string Name => @"AES-CBC";

		protected override ICryptoTransform Encryptor { get; }
		protected override ICryptoTransform Decryptor { get; }

		public AESCBCCrypto(byte[] key, byte[] iv) : base(key)
		{
			Encryptor = AESUtils.AesCbc.CreateEncryptor(key, iv);
			Decryptor = AESUtils.AesCbc.CreateDecryptor(key, iv);
		}
	}
}
