namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;

public class ChaCha20OriginalCryptoSF : ChaCha20OriginalCrypto
{
	public ChaCha20OriginalCryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset) { }

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
