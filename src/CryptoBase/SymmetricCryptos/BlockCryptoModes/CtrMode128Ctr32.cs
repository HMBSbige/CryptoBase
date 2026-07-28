namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CtrMode128Ctr32<TBlockCipher> : CtrMode128Core<TBlockCipher, CtrIncrementer32>
	where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public CtrMode128Ctr32(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true) : base(blockCipher, iv, disposeCipher)
	{
	}
}
