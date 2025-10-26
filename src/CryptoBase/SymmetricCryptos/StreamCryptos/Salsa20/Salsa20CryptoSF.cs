namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;

public class Salsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : Salsa20CryptoX86(key, iv)
{
	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return 0;
	}

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
