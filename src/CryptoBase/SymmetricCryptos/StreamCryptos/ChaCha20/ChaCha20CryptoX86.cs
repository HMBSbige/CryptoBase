namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public class ChaCha20CryptoX86 : ChaCha20CryptoSF
{
	public ChaCha20CryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override void UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination, ref int length, ref int sourceOffset, ref int destOffset)
	{
		Span<uint> stateSpan = State.AsSpan(0, 16);

		if (Avx.IsSupported && Avx2.IsSupported)
		{
			if (length >= 512)
			{
				ChaCha20Utils.ChaChaCore512(Rounds, stateSpan, source, destination, ref length, ref sourceOffset, ref destOffset);
			}

			while (length >= 128)
			{
				ChaCha20Utils.ChaChaCore128(Rounds, stateSpan, source.Slice(sourceOffset, 128), destination.Slice(destOffset, 128));

				sourceOffset += 128;
				destOffset += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				ChaCha20Utils.ChaChaCore256(Rounds, stateSpan, source, destination, ref length, ref sourceOffset, ref destOffset);
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCore64(Rounds, stateSpan, source.Slice(sourceOffset, 64), destination.Slice(destOffset, 64));

				sourceOffset += 64;
				destOffset += 64;
				length -= 64;
			}
		}
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
