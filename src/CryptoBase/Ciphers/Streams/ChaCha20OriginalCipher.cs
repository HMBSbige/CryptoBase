namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Provides the original ChaCha20 stream cipher with a 64-bit nonce and counter.
/// </summary>
public class ChaCha20OriginalCipher : SnuffleCipher
{
	/// <summary>The required nonce size, in bytes.</summary>
	public const int IVSize = 8;

	/// <summary>
	/// Initializes a new instance with the specified key and nonce.
	/// </summary>
	/// <param name="key">The 128- or 256-bit key.</param>
	/// <param name="iv">The 64-bit nonce.</param>
	public ChaCha20OriginalCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		Init(key, iv);
		SetCounter(0);
	}

	private protected ChaCha20OriginalCipher()
	{
	}

	// Slicing the key and nonce to their validated lengths gives the copies constant sizes, which the JIT unrolls instead of calling Memmove.
	private void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, IVSize, nameof(iv));

		Span<uint> state = StateSpan;

		switch (key.Length)
		{
			case 16:
			{
				ReadOnlySpan<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key.Slice(0, 16));
				Sigma16.CopyTo(state);
				keySpan.CopyTo(state.Slice(4));
				keySpan.CopyTo(state.Slice(8));
				break;
			}
			case 32:
			{
				Sigma32.CopyTo(state);
				MemoryMarshal.Cast<byte, uint>(key.Slice(0, 32)).CopyTo(state.Slice(4));
				break;
			}
			default:
			{
				ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key));
				return;
			}
		}

		MemoryMarshal.Cast<byte, uint>(iv.Slice(0, IVSize)).CopyTo(state.Slice(14));
	}

	/// <inheritdoc />
	protected override int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		return ChaCha20Utils.XorBlocks(stateSpan, source, destination);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.NoInlining)]
	protected override void UpdateKeyStream()
	{
		ChaCha20Utils.UpdateKeyStream(StateSpan, KeyStreamSpan);
	}

	/// <summary>Sets the block counter and resets the byte offset within the block to zero.</summary>
	/// <param name="counter">The counter value for the next 64-byte keystream block.</param>
	public void SetCounter(ulong counter)
	{
		CounterRemaining = GetBlocksRemaining(counter);
		Index = 0;
		ChaCha20Utils.GetCounterOriginal(ref StateRef) = counter;
	}

	/// <inheritdoc />
	protected override void IncrementCounter(Span<uint> state)
	{
		++ChaCha20Utils.GetCounterOriginal(ref MemoryMarshal.GetReference(state));
	}
}
