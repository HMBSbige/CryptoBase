namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CtrMode128<TBlockCipher> : CtrMode128Core<TBlockCipher, CtrIncrementer128>
	where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public CtrMode128(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true) : base(blockCipher, iv, disposeCipher)
	{
	}
}
