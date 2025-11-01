using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

public static class AEADCryptoCreate
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto AesGcm(ReadOnlySpan<byte> key)
	{
		if (DefaultAesGcmCrypto.IsSupported)
		{
			return new DefaultAesGcmCrypto(key);
		}

		return new GcmCryptoMode(AesCrypto.CreateCore(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto Sm4Gcm(ReadOnlySpan<byte> key)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			return new GcmCryptoModeBlock16X86(new SM4Crypto(key));
		}

		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			return new GcmCryptoModeBlock8X86(new SM4Crypto(key));
		}

		return new GcmCryptoMode(new SM4Crypto(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto ChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		if (OperatingSystem.IsWindows())
		{
			return new ChaCha20Poly1305Crypto(key);
		}

		if (DefaultChaCha20Poly1305Crypto.IsSupported)
		{
			return new DefaultChaCha20Poly1305Crypto(key);
		}

		return new ChaCha20Poly1305Crypto(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto XChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		return new XChaCha20Poly1305Crypto(key);
	}
}
