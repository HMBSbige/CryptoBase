namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public class ChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : ChaCha20Crypto(key, iv)
{
	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return 0;
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
