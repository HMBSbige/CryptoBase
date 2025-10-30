using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public static class StreamCryptoCreate
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return BlockCryptoModeCreate.Ctr(AesCrypto.CreateCore(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto Sm4Ctr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			return new CTR128StreamModeBlock16X86(new SM4CryptoBlock16X86(key), iv);
		}

		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported && Sse41.IsSupported)
		{
			return new CTR128StreamModeBlock8X86(new SM4CryptoBlock8X86(key), iv);
		}

		return BlockCryptoModeCreate.Ctr(new SM4Crypto(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto AesCfb(bool isEncrypt, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CFB128StreamMode(isEncrypt, AesCrypto.CreateCore(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto Sm4Cfb(bool isEncrypt, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CFB128StreamMode(isEncrypt, new SM4Crypto(key), iv);
	}
}
