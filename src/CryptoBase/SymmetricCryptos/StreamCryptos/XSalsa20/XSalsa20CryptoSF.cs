namespace CryptoBase.SymmetricCryptos.StreamCryptos.XSalsa20;

public class XSalsa20CryptoSF : XSalsa20CryptoX86
{
	public XSalsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void SalsaRound(uint[] x)
	{
		Salsa20Utils.SalsaRound(Rounds, x);
	}

	protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length) { }

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}

	protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		IntrinsicsUtils.Xor(stream, source, destination, length);
	}
}
