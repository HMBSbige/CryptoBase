namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20;

public class Salsa20CryptoSF : Salsa20CryptoX86
{
	public Salsa20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset) { }

	protected override void UpdateKeyStream()
	{
		Salsa20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
