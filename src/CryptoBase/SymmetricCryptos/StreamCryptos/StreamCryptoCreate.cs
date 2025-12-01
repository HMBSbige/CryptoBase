using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.AES;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public static class StreamCryptoCreate
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CtrMode128<AesCipher>(AesCipher.Create(key), iv);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto Sm4Ctr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CtrMode128<Sm4Cipher>(Sm4Cipher.Create(key), iv);
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
