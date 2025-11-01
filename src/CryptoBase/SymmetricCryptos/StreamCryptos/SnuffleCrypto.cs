using CryptoBase.Abstractions.SymmetricCryptos;

namespace CryptoBase.SymmetricCryptos.StreamCryptos;

public abstract class SnuffleCrypto : SnuffleCryptoBase
{
	/// <summary>
	/// expand 16-byte k
	/// </summary>
	protected static readonly uint[] Sigma16 = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

	/// <summary>
	/// expand 32-byte k
	/// </summary>
	protected static readonly uint[] Sigma32 = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

	protected byte Rounds { get; init; } = 20;

	protected readonly CryptoArrayPool<uint> State = new(StateSize);
	protected readonly CryptoArrayPool<byte> KeyStream = new(BlockSize);

	protected int Index;
	protected ulong CounterRemaining;

	/// <summary>
	/// Maximum counter value (number of blocks that can be processed)
	/// </summary>
	protected virtual ulong MaxCounter => ulong.MaxValue;

	public override void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Update(source, destination);

		long blocksNeeded = ((uint)source.Length + Index + BlockSize - 1) / BlockSize - ((Index | -Index) >> 31 & 1);

		if ((ulong)blocksNeeded > CounterRemaining)
		{
			ThrowHelper.ThrowDataLimitExceeded(nameof(source));
		}

		int i = 0;
		int left = source.Length;

		Span<uint> state = State.Span;
		Span<byte> keyStream = KeyStream.Span;

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
			if (Index is 0)
			{
				UpdateKeyStream();
				IncrementCounter(state);
				--CounterRemaining;
			}

			FastUtils.Xor(keyStream.Slice(Index), source.Slice(i), destination.Slice(i), left);

			Index += left;
			Index &= BlockSize - 1;
		}
	}

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

	protected abstract void UpdateKeyStream();
	protected abstract void IncrementCounter(Span<uint> state);

	public override void Dispose()
	{
		State.Dispose();
		KeyStream.Dispose();

		base.Dispose();
		GC.SuppressFinalize(this);
	}
}
