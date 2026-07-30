namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// Provides CTR mode with a big-endian 128-bit counter.
/// </summary>
/// <typeparam name="TBlockCipher">The block cipher type.</typeparam>
/// <param name="blockCipher">The block cipher.</param>
/// <param name="iv">The initial counter block, up to 16 bytes. Shorter values occupy the leading bytes and are followed by zeros.</param>
/// <param name="disposeCipher">Whether to dispose <paramref name="blockCipher"/> with this instance.</param>
public sealed class CtrMode128<TBlockCipher>(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true) : CtrMode128Core<TBlockCipher, CtrIncrementer128>(blockCipher, iv, disposeCipher)
	where TBlockCipher : IBlock16Cipher<TBlockCipher>;
