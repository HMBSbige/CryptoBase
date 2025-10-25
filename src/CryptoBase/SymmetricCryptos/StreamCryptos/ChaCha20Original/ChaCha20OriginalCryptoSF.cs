namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;

public class ChaCha20OriginalCryptoSF : ChaCha20OriginalCrypto
{
	public ChaCha20OriginalCryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return 0;
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
