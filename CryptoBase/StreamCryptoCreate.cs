using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using CryptoBase.SymmetricCryptos.StreamCryptos.RC4;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class StreamCryptoCreate
	{
		private static readonly byte[] EmptyIv12 = new byte[12];
		private static readonly byte[] EmptyIv24 = new byte[24];

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IStreamCrypto AesCtr(byte[] key, byte[] iv)
		{
			return new CTRStreamMode(AESUtils.CreateECB(key), iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IStreamCrypto Sm4Ctr(byte[] key, byte[] iv)
		{
			return new CTRStreamMode(new SM4Crypto(key), iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IStreamCrypto AesCfb(bool isEncrypt, byte[] key, byte[] iv)
		{
			return new CFB128StreamMode(isEncrypt, AESUtils.CreateECB(key), iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IStreamCrypto Sm4Cfb(bool isEncrypt, byte[] key, byte[] iv)
		{
			return new CFB128StreamMode(isEncrypt, new SM4Crypto(key), iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IStreamCrypto Rc4(byte[] key)
		{
			return new RC4Crypto(key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ChaCha20OriginalCrypto ChaCha20Original(byte[] key, byte[] iv)
		{
			if (Sse2.IsSupported)
			{
				return new ChaCha20OriginalCryptoX86(key, iv);
			}

			return new ChaCha20OriginalCryptoSF(key, iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ChaCha20Crypto ChaCha20(byte[] key, byte[] iv)
		{
			if (Sse2.IsSupported)
			{
				return new ChaCha20CryptoX86(key, iv);
			}

			return new ChaCha20CryptoSF(key, iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ChaCha20Crypto ChaCha20(byte[] key)
		{
			return ChaCha20(key, EmptyIv12);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static XChaCha20Crypto XChaCha20(byte[] key, byte[] iv)
		{
			if (Sse2.IsSupported)
			{
				return new XChaCha20CryptoX86(key, iv);
			}

			return new XChaCha20CryptoSF(key, iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static XChaCha20Crypto XChaCha20(byte[] key)
		{
			return XChaCha20(key, EmptyIv24);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Salsa20Crypto Salsa20(byte[] key, byte[] iv)
		{
			if (Sse2.IsSupported)
			{
				return new Salsa20CryptoX86(key, iv);
			}

			return new Salsa20CryptoSF(key, iv);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Salsa20Crypto XSalsa20(byte[] key, byte[] iv)
		{
			if (Sse2.IsSupported)
			{
				return new XSalsa20CryptoX86(key, iv);
			}

			return new XSalsa20CryptoSF(key, iv);
		}
	}
}
