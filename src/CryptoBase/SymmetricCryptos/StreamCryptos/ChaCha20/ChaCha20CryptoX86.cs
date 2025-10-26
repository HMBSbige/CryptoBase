namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20;

public class ChaCha20CryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : ChaCha20CryptoSF(key, iv)
{
	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;
		Span<uint> stateSpan = State.AsSpan();

		if (Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int offset = ChaCha20Utils.ChaChaCore512(Rounds, stateSpan, source, destination);
				processed += offset;
				length -= offset;
			}

			while (length >= 128)
			{
				ChaCha20Utils.ChaChaCore128(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int offset = ChaCha20Utils.ChaChaCore256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
				processed += offset;
				length -= offset;
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCore64(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 64;
				length -= 64;
			}
		}

		return processed;
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(State, KeyStream, Rounds);
	}
}
