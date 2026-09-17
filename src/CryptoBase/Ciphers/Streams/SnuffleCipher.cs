namespace CryptoBase.Ciphers.Streams;

/// <summary>
/// Provides shared state and block processing for Salsa- and ChaCha-family stream ciphers.
/// </summary>
public abstract class SnuffleCipher : IStreamCipher
{
	/// <summary>Gets the block size, in bytes.</summary>
	protected const int BlockSize = 64;

	/// <summary>
	/// expand 16-byte k
	/// </summary>
	protected static ReadOnlySpan<uint> Sigma16 => [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

	/// <summary>
	/// expand 32-byte k
	/// </summary>
	protected static ReadOnlySpan<uint> Sigma32 => [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

	/// <summary>
	/// The number of cipher rounds.
	/// </summary>
	protected internal const byte Rounds = 20;

	/// <summary>
	/// Stores the cipher state.
	/// </summary>
	protected InlineArray16<uint> State;

	/// <summary>
	/// Stores the current keystream block.
	/// </summary>
	protected InlineArray16<uint> KeyStream;

	/// <summary>
	/// Gets the cipher state as 32-bit words.
	/// </summary>
	protected Span<uint> StateSpan
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => State;
	}

	/// <summary>
	/// Gets the current keystream block as bytes.
	/// </summary>
	protected Span<byte> KeyStreamSpan
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => KeyStream.AsSpan();
	}

	/// <summary>
	/// Gets a reference to the first cipher-state word.
	/// </summary>
	protected ref uint StateRef
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => ref State[0];
	}

	/// <summary>
	/// The current position in the keystream block.
	/// </summary>
	protected int Index;

	/// <summary>
	/// The number of blocks available before counter exhaustion.
	/// </summary>
	protected ulong CounterRemaining;

	/// <summary>
	/// Maximum counter value (number of blocks that can be processed)
	/// </summary>
	protected virtual ulong MaxCounter => ulong.MaxValue;

	/// <inheritdoc />
	public void Xor(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CipherBufferGuard.Output(source, destination);

		long blocksNeeded = ((uint)source.Length + Index + BlockSize - 1) / BlockSize - ((Index | -Index) >> 31 & 1);

		if ((ulong)blocksNeeded > CounterRemaining)
		{
			ThrowHelper.ThrowDataLimitExceeded(nameof(source));
		}

		int i = 0;
		int left = source.Length;

		Span<uint> state = StateSpan;
		Span<byte> keyStream = KeyStreamSpan;

		if (Index is not 0 && left > 0)
		{
			int r = BlockSize - Index;
			int n = Math.Min(r, left);

			FastUtils.Xor(keyStream.Slice(Index), source, destination, n);

			Index += n;
			Index &= BlockSize - 1;
			i += n;
			left -= n;
		}

		if (left >= BlockSize)
		{
			int processed = UpdateBlocks(state, keyStream, source.Slice(i), destination.Slice(i));
			CounterRemaining -= (uint)processed / BlockSize;

			i += processed;
			left -= processed;
		}

		if (left > 0)
		{
			UpdateKeyStream();
			IncrementCounter(state);
			--CounterRemaining;

			FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), left);

			Index = left;
		}
	}

	/// <summary>
	/// Processes complete cipher blocks.
	/// </summary>
	/// <param name="stateSpan">The cipher state.</param>
	/// <param name="keyStream">The keystream buffer.</param>
	/// <param name="source">The input data.</param>
	/// <param name="destination">The output destination.</param>
	/// <returns>The number of bytes processed.</returns>
	protected virtual int UpdateBlocks(in Span<uint> stateSpan, in Span<byte> keyStream, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int i = 0;
		int left = source.Length;

		while (left >= BlockSize)
		{
			UpdateKeyStream();
			IncrementCounter(stateSpan);

			FastUtils.Xor(keyStream, source.Slice(i), destination.Slice(i), BlockSize);

			i += BlockSize;
			left -= BlockSize;
		}

		return source.Length - left;
	}

	/// <summary>
	/// Generates the current keystream block.
	/// </summary>
	protected abstract void UpdateKeyStream();

	/// <summary>
	/// Increments the block counter in the specified cipher state.
	/// </summary>
	/// <param name="state">The cipher state.</param>
	protected abstract void IncrementCounter(Span<uint> state);

	/// <inheritdoc />
	public virtual void Dispose()
	{
		State.ZeroMemory();
		KeyStream.ZeroMemory();

		GC.SuppressFinalize(this);
	}
}
