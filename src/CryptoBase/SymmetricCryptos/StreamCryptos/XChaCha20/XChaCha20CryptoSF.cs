namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;

public class XChaCha20CryptoSF : XChaCha20Crypto
{
	public XChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void ChaChaRound(uint[] x)
	{
		ChaCha20Utils.ChaChaRound(Rounds, x);
	}

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset) { }

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
