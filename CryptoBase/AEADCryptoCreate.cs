using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos;
using CryptoBase.SymmetricCryptos.AEADCryptos.GCM;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using System;
using System.Runtime.CompilerServices;

namespace CryptoBase
{
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
}
