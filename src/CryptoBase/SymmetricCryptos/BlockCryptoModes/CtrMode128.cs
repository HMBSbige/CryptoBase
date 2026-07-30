namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CtrMode128<TBlockCipher>(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true) : CtrMode128Core<TBlockCipher, CtrIncrementer128>(blockCipher, iv, disposeCipher)
	where TBlockCipher : IBlock16Cipher<TBlockCipher>;
