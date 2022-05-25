using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public static class BlockCryptoModeCreate
{
	public static IStreamBlockCryptoMode Ctr(IBlockCrypto crypto, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported && Ssse3.IsSupported && Sse41.IsSupported)
		{
			return new CTR128StreamModeX86(crypto, iv);
		}
		return new CTR128StreamMode(crypto, iv);
	}
}
