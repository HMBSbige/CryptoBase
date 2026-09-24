namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashSoftware
{
	internal static void AppendPaddedSegments(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		State state = new(in key, in accumulator);
		Vector128<byte> finalBlock = default;

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			state.CopyAccumulatorTo(ref accumulator);
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	private struct State
	{
		private readonly ulong _keyHigh;
		private readonly ulong _keyLow;
		private ulong _accumulatorHigh;
		private ulong _accumulatorLow;

		internal State(in Vector128<byte> key, in Vector128<byte> accumulator)
		{
			ReadOnlySpan<byte> keyBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(in key, 1));
			ReadOnlySpan<byte> accumulatorBytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(in accumulator, 1));
			_keyHigh = BinaryPrimitives.ReadUInt64BigEndian(keyBytes);
			_keyLow = BinaryPrimitives.ReadUInt64BigEndian(keyBytes.Slice(8));
			_accumulatorHigh = BinaryPrimitives.ReadUInt64BigEndian(accumulatorBytes);
			_accumulatorLow = BinaryPrimitives.ReadUInt64BigEndian(accumulatorBytes.Slice(8));

			if (Environment.Is64BitProcess)
			{
				InitializeKey64(ref _keyHigh, ref _keyLow);
			}
		}

		private void AppendBlocks(ReadOnlySpan<byte> source)
		{
			while (source.Length >= GHash.BlockSizeInBytes)
			{
				ReadOnlySpan<byte> block = source.Slice(0, GHash.BlockSizeInBytes);
				_accumulatorHigh ^= BinaryPrimitives.ReadUInt64BigEndian(block);
				_accumulatorLow ^= BinaryPrimitives.ReadUInt64BigEndian(block.Slice(8));

				// Use uint multiplication on 32-bit processes to avoid variable-time ulong helpers.
				if (Environment.Is64BitProcess)
				{
					Multiply64(ref _accumulatorHigh, ref _accumulatorLow, _keyHigh, _keyLow);
				}
				else
				{
					Multiply32(ref _accumulatorHigh, ref _accumulatorLow, _keyHigh, _keyLow);
				}

				source = source.Slice(GHash.BlockSizeInBytes);
			}
		}

		internal void AppendPaddedSegment(ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
		{
			int completeLength = source.Length & -GHash.BlockSizeInBytes;
			AppendBlocks(source.Slice(0, completeLength));
			ReadOnlySpan<byte> remaining = source.Slice(completeLength);

			if (remaining.IsEmpty)
			{
				return;
			}

			finalBlock = default;
			remaining.CopyTo(finalBlock.AsSpan());
			AppendBlocks(finalBlock.AsReadOnlySpan());
		}

		internal readonly void CopyAccumulatorTo(ref Vector128<byte> destination)
		{
			Span<byte> bytes = destination.AsSpan();
			BinaryPrimitives.WriteUInt64BigEndian(bytes, _accumulatorHigh);
			BinaryPrimitives.WriteUInt64BigEndian(bytes.Slice(8), _accumulatorLow);
		}
	}
}
