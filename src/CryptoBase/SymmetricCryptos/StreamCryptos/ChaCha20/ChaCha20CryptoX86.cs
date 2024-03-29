namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public class ChaCha20CryptoX86 : ChaCha20CryptoSF
{
	public ChaCha20CryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override unsafe void UpdateBlocks(ref uint* state, ref byte* source, ref byte* destination, ref int length)
	{
		if (Avx.IsSupported && Avx2.IsSupported)
		{
			if (length >= 512)
			{
				ChaCha20Utils.ChaChaCore512(Rounds, state, ref source, ref destination, ref length);
			}

			while (length >= 128)
			{
				ChaCha20Utils.ChaChaCore128(Rounds, state, source, destination);

				source += 128;
				destination += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				ChaCha20Utils.ChaChaCore256(Rounds, state, ref source, ref destination, ref length);
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCore64(Rounds, state, source, destination);

				source += 64;
				destination += 64;
				length -= 64;
			}
		}
	}

	protected override unsafe void UpdateKeyStream()
	{
		fixed (uint* x = State)
		fixed (byte* s = KeyStream)
		{
			ChaCha20Utils.UpdateKeyStream(x, s, Rounds);
		}
	}
}
