namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CtrMode128Ctr32<TBlockCipher>(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true) : CtrMode128Core<TBlockCipher, CtrIncrementer32>(blockCipher, iv, disposeCipher)
	where TBlockCipher : IBlock16Cipher<TBlockCipher>;
