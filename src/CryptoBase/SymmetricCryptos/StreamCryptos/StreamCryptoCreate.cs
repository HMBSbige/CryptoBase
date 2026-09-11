using CryptoBase.SymmetricCryptos.BlockCryptoModes;
using CryptoBase.SymmetricCryptos.BlockCryptos.Aes;
using CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

/// <summary>
/// Provides factory methods for streaming block-cipher modes.
/// </summary>
public static class StreamCryptoCreate
{
	/// <summary>
	/// Creates an AES-CTR cipher.
	/// </summary>
	/// <param name="key">The 16-, 24-, or 32-byte AES key.</param>
	/// <param name="iv">The initial counter block, up to 16 bytes. Shorter values occupy the leading bytes and are followed by zeros.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto AesCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CtrMode128<AesCipher>(AesCipher.Create(key), iv);
	}

	/// <summary>
	/// Creates an SM4-CTR cipher.
	/// </summary>
	/// <param name="key">The 16-byte SM4 key.</param>
	/// <param name="iv">The initial counter block, up to 16 bytes. Shorter values occupy the leading bytes and are followed by zeros.</param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static IStreamCrypto SM4Ctr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		return new CtrMode128<SM4Cipher>(SM4Cipher.Create(key), iv);
	}
}
