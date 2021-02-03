using System;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public static class AESUtils
	{
		public static bool IsSupportX86 => Aes.IsSupported && Sse2.IsSupported;

		public static AESCrypto Create(byte[] key)
		{
			if (IsSupportX86)
			{
				return key.Length switch
				{
					16 => new FastAESCrypto128(key),
					24 => new FastAESCrypto192(key),
					32 => new FastAESCrypto256(key),
					_ => throw new ArgumentOutOfRangeException(nameof(key))
				};
			}

			return new NormalAES(key);
		}
	}
}
