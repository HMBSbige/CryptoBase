using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

public static class AEADCryptoCreate
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto AesGcm(ReadOnlySpan<byte> key)
	{
		return new DefaultAesGcmCrypto(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto Sm4Gcm(ReadOnlySpan<byte> key)
	{
		if (Aes.IsSupported && Avx.IsSupported && Avx2.IsSupported)
		{
			return new GcmCryptoModeBlock16X86(new SM4Crypto(key), new SM4CryptoBlock16X86(key));
		}

		if (Aes.IsSupported && Sse2.IsSupported && Ssse3.IsSupported && Sse41.IsSupported)
		{
			return new GcmCryptoModeBlock8X86(new SM4Crypto(key), new SM4CryptoBlock8X86(key));
		}

		return new GcmCryptoMode(new SM4Crypto(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto ChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		return new ChaCha20Poly1305Crypto(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto XChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		return new XChaCha20Poly1305Crypto(key);
	}
}
