namespace CryptoBase.SymmetricCryptos.StreamCryptos;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc8439
/// </summary>
public class ChaCha20Crypto : SnuffleCrypto
{
	/// <inheritdoc />
	public override string Name => @"ChaCha20";

	/// <inheritdoc />
	public override int IvSize => 12;

	/// <inheritdoc />
	protected override ulong MaxCounter => uint.MaxValue;

	/// <summary>
	/// The required key size, in bytes.
	/// </summary>
	public const int KeySize = 32;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 256-bit key.</param>
	/// <param name="iv">The 96-bit nonce.</param>
	public ChaCha20Crypto(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		SetCounter(0);
	}

	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, KeySize, nameof(key));

		Span<uint> state = StateSpan;
		state[0] = Sigma32[0];
		state[1] = Sigma32[1];
		state[2] = Sigma32[2];
		state[3] = Sigma32[3];

		ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key);
		keySpan.CopyTo(state.Slice(4));

		SetIV(iv);
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int processed = 0;
		int length = source.Length;

		if (Avx512F.IsSupported)
		{
			if (length >= 2048)
			{
				int offset = ChaCha20Utils.ChaChaCoreSoA2048Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += offset;
				length -= offset;
			}

			if (length >= 1024)
			{
				int offset = ChaCha20Utils.ChaChaCoreSoA1024Avx512(Rounds, stateSpan, source.Slice(processed), destination.Slice(processed));

				processed += offset;
				length -= offset;
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

	/// <inheritdoc />
	protected override void UpdateKeyStream()
	{
		if (Sse2.IsSupported)
		{
			ChaCha20Utils.UpdateKeyStream(StateSpan, KeyStreamSpan, Rounds);
		}
		else
		{
			ChaCha20Utils.UpdateKeyStream(Rounds, StateSpan, KeyStreamSpan);
		}
	}

	/// <inheritdoc />
	public override void Reset()
	{
		SetCounter(0);
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounter(ref state.GetReference());
	}

	/// <summary>
	/// Sets the 96-bit nonce.
	/// </summary>
	/// <param name="iv">The nonce.</param>
	public void SetIV(ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IvSize, nameof(iv));

		ReadOnlySpan<uint> ivSpan = MemoryMarshal.Cast<byte, uint>(iv);
		Span<uint> state = StateSpan;
		state[13] = ivSpan[0];
		state[14] = ivSpan[1];
		state[15] = ivSpan[2];
	}

	/// <summary>
	/// Sets the 32-bit block counter.
	/// </summary>
	/// <param name="counter">The counter value.</param>
	public void SetCounter(uint counter)
	{
		CounterRemaining = MaxCounter - counter;
		Index = 0;
		ChaCha20Utils.GetCounter(ref StateRef) = counter;
	}
}
