using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptoModes.CTR;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;
using CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;
using CryptoBase.SymmetricCryptos.StreamCryptos.RC4;
using CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;
using CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;
using CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public static class StreamCryptoCreate
{
	private static ReadOnlySpan<byte> EmptyIv12 => "\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	private static ReadOnlySpan<byte> EmptyIv24 => "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return BlockCryptoModeCreate.Ctr(AESUtils.CreateECB(key), iv);
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
		return new CFB128StreamMode(isEncrypt, AESUtils.CreateECB(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto Sm4Cfb(bool isEncrypt, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CFB128StreamMode(isEncrypt, new SM4Crypto(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto Rc4(ReadOnlySpan<byte> key)
	{
		return new RC4Crypto(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ChaCha20OriginalCrypto ChaCha20Original(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported)
		{
			return new ChaCha20OriginalCryptoX86(key, iv);
		}

		return new ChaCha20OriginalCryptoSF(key, iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ChaCha20Crypto ChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported)
		{
			return new ChaCha20CryptoX86(key, iv);
		}

		return new ChaCha20CryptoSF(key, iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ChaCha20Crypto ChaCha20(ReadOnlySpan<byte> key)
	{
		return ChaCha20(key, EmptyIv12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static XChaCha20Crypto XChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported)
		{
			return new XChaCha20CryptoX86(key, iv);
		}

		return new XChaCha20CryptoSF(key, iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static XChaCha20Crypto XChaCha20(ReadOnlySpan<byte> key)
	{
		return XChaCha20(key, EmptyIv24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Salsa20Crypto Salsa20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported)
		{
			return new Salsa20CryptoX86(key, iv);
		}

		return new Salsa20CryptoSF(key, iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Salsa20Crypto XSalsa20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		if (Sse2.IsSupported)
		{
			return new XSalsa20CryptoX86(key, iv);
		}

		return new XSalsa20CryptoSF(key, iv);
	}
}
