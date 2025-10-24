using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.Xts;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public static class BlockCryptoModeCreate
{
	public static IStreamCrypto Ctr(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported && Ssse3.IsSupported && Sse41.IsSupported)
		{
			return new CTR128StreamModeX86(crypto, iv);
		}

		return new CTR128StreamMode(crypto, iv);
	}

	public static IBlockCrypto AesXts(ReadOnlySpan<byte> key1, ReadOnlySpan<byte> key2, ReadOnlySpan<byte> iv)
	{
		return new XtsMode(AESUtils.CreateECB(key1), AESUtils.CreateECB(key2), iv);
	}
}
