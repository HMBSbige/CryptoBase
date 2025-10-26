namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;

public class XSalsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : XSalsa20CryptoX86(key, iv)
{
	protected override void SalsaRound(uint[] x)
	{
		Salsa20Utils.SalsaRound(Rounds, x);
	}

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return 0;
	}

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
