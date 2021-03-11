using System;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public abstract class AESCryptoX86 : AESCrypto
	{
		protected AESCryptoX86(ReadOnlySpan<byte> key) : base(key) { }
	}
}
