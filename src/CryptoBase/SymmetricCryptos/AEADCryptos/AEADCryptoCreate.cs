using CryptoBase.SymmetricCryptos.BlockCryptoModes;
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

		return new GcmMode128(AesCrypto.CreateCore(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto Sm4Gcm(ReadOnlySpan<byte> key)
	{
		return new GcmMode128(new SM4Crypto(key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto ChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		if (OperatingSystem.IsWindows() && Sse2.IsSupported)
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
