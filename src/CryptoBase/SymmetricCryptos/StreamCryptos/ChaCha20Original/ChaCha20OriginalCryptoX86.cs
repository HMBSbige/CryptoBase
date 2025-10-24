namespace CryptoBase.SymmetricCryptos.StreamCryptos.ChaCha20Original;

public class ChaCha20OriginalCryptoX86 : ChaCha20OriginalCryptoSF
{
	public ChaCha20OriginalCryptoX86(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : base(key, iv) { }

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;
		Span<uint> stateSpan = State.AsSpan(0, 16);

		if (Avx.IsSupported && Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int tempLength = length;
				int tempSourceOffset = 0;
				int tempDestOffset = 0;
				ChaCha20Utils.ChaChaCoreOriginal512(Rounds, stateSpan, source, destination, ref tempLength, ref tempSourceOffset, ref tempDestOffset);
				processed += tempSourceOffset;
				length = tempLength;
			}

			while (length >= 128)
			{
				ChaCha20Utils.ChaChaCoreOriginal128(Rounds, stateSpan, source.Slice(processed, 128), destination.Slice(processed, 128));

				processed += 128;
				length -= 128;
			}
		}

		if (Sse2.IsSupported)
		{
			if (length >= 256)
			{
				int tempLength = length;
				int tempSourceOffset = 0;
				int tempDestOffset = 0;
				ChaCha20Utils.ChaChaCoreOriginal256(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed), ref tempLength, ref tempSourceOffset, ref tempDestOffset);
				processed += tempSourceOffset;
				length = tempLength;
			}

			while (length >= 64)
			{
				ChaCha20Utils.ChaChaCoreOriginal64(Rounds, stateSpan, source.Slice(processed, 64), destination.Slice(processed, 64));

				processed += 64;
				length -= 64;
			}
		}

		return processed;
	}

	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(State.AsSpan(0, 16), KeyStream.AsSpan(0, 64), Rounds);
	}
}
