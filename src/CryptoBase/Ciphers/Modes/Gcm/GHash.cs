namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHash
{
	internal const int BlockSizeInBytes = 16;

	private Vector128<byte> _key;
	private Vector128<byte> _accumulator;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static long GetPaddedLength(int length)
	{
		return (long)length + BlockSizeInBytes - 1 & -BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static GHash Create(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, BlockSizeInBytes, nameof(key));
		return new GHash { _key = Vector128.LoadUnsafe(ref key.GetReference()) };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_accumulator = default;
	}

	// Appends one independently padded segment to the keyed state.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void AppendPaddedSegment(ReadOnlySpan<byte> source)
	{
		AppendPaddedSegments(ref _accumulator, in _key, source, default, default);
	}

	// Hashes three independently padded segments and resets the keyed state.
	internal int HashPaddedSegmentsAndReset(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSizeInBytes, nameof(destination));
		AppendPaddedSegments(ref _accumulator, in _key, first, second, third);
		WriteHash(in _accumulator, destination);
		Reset();
		return BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteHash(in Vector128<byte> accumulator, Span<byte> destination)
	{
		ReadOnlySpan<byte> hash = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(in accumulator, 1));
		hash.CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendPaddedSegments(ref Vector128<byte> accumulator, in Vector128<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		if (GHashX86.IsSupported)
		{
			GHashX86.AppendPaddedSegments(ref accumulator, in key, first, second, third);
		}
		else if (GHashArm.IsSupported)
		{
			GHashArm.AppendPaddedSegments(ref accumulator, in key, first, second, third);
		}
		else
		{
			GHashSoftware.AppendPaddedSegments(ref accumulator, in key, first, second, third);
		}
	}
}
