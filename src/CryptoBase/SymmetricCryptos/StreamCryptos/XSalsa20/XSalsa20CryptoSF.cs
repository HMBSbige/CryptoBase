namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;

public class XSalsa20CryptoSF : XSalsa20CryptoX86
{
	public XSalsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void SalsaRound(uint[] x)
	{
		Salsa20Utils.SalsaRound(Rounds, x);
	}

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset) { }

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}
}
