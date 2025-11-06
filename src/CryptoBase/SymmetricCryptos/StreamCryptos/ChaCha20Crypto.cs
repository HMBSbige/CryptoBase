namespace CryptoBase.SymmetricCryptos.StreamCryptos;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8439
/// </summary>
public class ChaCha20Crypto : SnuffleCrypto
{
	public override string Name => @"ChaCha20";

	public override int IvSize => 12;

	protected override ulong MaxCounter => uint.MaxValue;

	public const int KeySize = 32;

	public ChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		SetCounter(0);
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		Span<uint> state = State.Span;
		state[0] = Sigma32[0];
		state[1] = Sigma32[1];
		state[2] = Sigma32[2];
		state[3] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(state.Slice(4));

		SetIV(iv);
	}

	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;

		if (Avx512F.IsSupported)
		{
			while (length >= 2048)
			{
				ChaCha20Utils.ChaChaCoreAoS2048Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 2048;
				length -= 2048;
			}

			while (length >= 1024)
			{
				ChaCha20Utils.ChaChaCoreAoS1024Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += 1024;
				length -= 1024;
			}
		}

		if (Avx2.IsSupported)
		{
			if (length >= 512)
			{
				int offset = ChaCha20Utils.ChaChaCore512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));
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

		if (length >= BlockSize)
		{
			processed += base.UpdateBlocks(stateSpan, keyStream, source.Slice(processed), destination.Slice(processed));
		}

		return processed;
	}

	protected override void UpdateKeyStream()
	{
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.UpdateKeyStream(State.Span, KeyStream.Span, Rounds);
		}
		else
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, State.Span, KeyStream.Span);
		}
	}

	public override void Reset()
	{
		SetCounter(0);
	}

	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounter(ref state.GetReference());
	}

	public void SetIV(ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IvSize, nameof(iv));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		State[13] = ivSpan[0];
		State[14] = ivSpan[1];
		State[15] = ivSpan[2];
	}

	public void SetCounter(uint counter)
	{
		CounterRemaining = MaxCounter - counter;
		Index = 0;
		ChaCha20Utils.GetCounter(ref State.GetReference()) = counter;
	}
}
