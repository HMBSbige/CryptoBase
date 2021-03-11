using System;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public sealed class AESCBCCrypto : DefaultAESCrypto
	{
		public override string Name => @"AES-CBC";

		protected override ICryptoTransform Encryptor { get; }
		protected override ICryptoTransform Decryptor { get; }

		public AESCBCCrypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key)
		{
			Encryptor = AESUtils.AesCbc.CreateEncryptor(key.ToArray(), iv.ToArray());
			Decryptor = AESUtils.AesCbc.CreateDecryptor(key.ToArray(), iv.ToArray());
		}
	}
}
