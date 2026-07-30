using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.AEADCryptos;

/// <summary>
/// Provides factory methods for authenticated encryption algorithms.
/// </summary>
public static class AEADCryptoCreate
{
	/// <summary>
	/// Creates an AES-GCM instance using 12-byte nonces and 16-byte tags.
	/// </summary>
	/// <param name="key">The 16-, 24-, or 32-byte key.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto AesGcm(ReadOnlySpan<byte> key)
	{
		if (DefaultAesGcmCrypto.IsSupported)
		{
			return new DefaultAesGcmCrypto(key);
		}

		return new GcmMode128<AesCipher>(AesCipher.Create(key));
	}

	/// <summary>
	/// Creates an SM4-GCM instance using 12-byte nonces and 16-byte tags.
	/// </summary>
	/// <param name="key">The 16-byte key.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto Sm4Gcm(ReadOnlySpan<byte> key)
	{
		return new GcmMode128<Sm4Cipher>(Sm4Cipher.Create(key));
	}

	/// <summary>
	/// Creates a ChaCha20-Poly1305 instance using 12-byte nonces and 16-byte tags.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
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

	/// <summary>
	/// Creates an XChaCha20-Poly1305 instance using 24-byte nonces and 16-byte tags.
	/// </summary>
	/// <param name="key">The 32-byte key.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IAEADCrypto XChaCha20Poly1305(ReadOnlySpan<byte> key)
	{
		return new XChaCha20Poly1305Crypto(key);
	}
}
