using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public sealed class AESECBCrypto : NormalAESCrypto
	{
		protected override ICryptoTransform Encryptor { get; }
		protected override ICryptoTransform Decryptor { get; }

		public AESECBCrypto(byte[] key) : base(key)
		{
			Encryptor = AESUtils.AesEcb.CreateEncryptor(key, null);
			Decryptor = AESUtils.AesEcb.CreateDecryptor(key, null);
		}
	}
}
