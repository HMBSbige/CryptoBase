namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public class ChaCha20CryptoSF : ChaCha20Crypto
{
	public ChaCha20CryptoSF(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length)
	{
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
	}

	protected override unsafe void Xor(byte* stream, byte* source, byte* destination, int length)
	{
		IntrinsicsUtils.Xor(stream, source, destination, length);
	}
}
