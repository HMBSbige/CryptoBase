using System;
using System.Security.Cryptography;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class AESECBCrypto : DefaultAESCrypto
{
	protected override ICryptoTransform Encryptor { get; }
	protected override ICryptoTransform Decryptor { get; }

	public AESECBCrypto(ReadOnlySpan<byte> key) : base(key)
	{
		Encryptor = AESUtils.AesEcb.CreateEncryptor(key.ToArray(), null);
		Decryptor = AESUtils.AesEcb.CreateDecryptor(key.ToArray(), null);
	}
}
