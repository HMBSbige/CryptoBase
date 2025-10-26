namespace CryptoBase.SymmetricCryptos.StreamCryptos.XChaCha20;

public class XChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : XChaCha20Crypto(key, iv)
{
	protected override void ChaChaRound(uint[] x)
	{
		ChaCha20Utils.ChaChaRound(Rounds, x);
	}

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return 0;
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
