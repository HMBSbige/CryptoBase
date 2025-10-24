namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;

public class XChaCha20CryptoSF : XChaCha20Crypto
{
	public XChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void ChaChaRound(uint[] x)
	{
		ChaCha20Utils.ChaChaRound(x.AsSpan(), Rounds);
	}

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset) { }

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
