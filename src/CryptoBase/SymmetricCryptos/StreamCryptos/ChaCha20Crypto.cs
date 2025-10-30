namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public class ChaCha20Crypto : SnuffleCrypto
{
	public override string Name => @"ChaCha20";

	public override int IvSize => 12;

	public ChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		Reset();
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 32, nameof(key));

		State[0] = Sigma32[0];
		State[1] = Sigma32[1];
		State[2] = Sigma32[2];
		State[3] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(State.AsSpan(4));

		SetIV(iv);
	}

	protected override int UpdateBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;
		Span<uint> stateSpan = State.AsSpan(0, StateSize);

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
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.UpdateKeyStream(State, KeyStream, Rounds);
		}
		else
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State, KeyStream);
		}
	}

	public sealed override void Reset()
	{
		SetCounter(0);
	}

	protected override void IncrementCounter(Span<uint> state)
	{
		ChaCha20Utils.IncrementCounter(state);
	}

	public void SetIV(ReadOnlySpan<byte> iv)
	{
		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		State[13] = ivSpan[0];
		State[14] = ivSpan[1];
		State[15] = ivSpan[2];
	}

	public void SetCounter(uint counter)
	{
		Index = 0;
		State[12] = counter;
	}
}
