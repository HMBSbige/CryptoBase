using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System.Runtime.CompilerServices;

namespace CryptoBase
{
	public static class AEADCryptoCreate
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static IAEADCrypto AesGcm(byte[] key)
		{
			return new DefaultAesGcmCrypto(key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static IAEADCrypto Sm4Gcm(byte[] key)
		{
			return new GcmCryptoMode(new SM4Crypto(key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static IAEADCrypto ChaCha20Poly1305(byte[] key)
		{
			return new ChaCha20Poly1305Crypto(key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static IAEADCrypto XChaCha20Poly1305(byte[] key)
		{
			return new XChaCha20Poly1305Crypto(key);
		}
	}
}
