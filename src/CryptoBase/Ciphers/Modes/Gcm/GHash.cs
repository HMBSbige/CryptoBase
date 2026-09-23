namespace CryptoBase.Ciphers.Modes.Gcm;

internal ref struct GHash : IDisposable
{
	internal const int BlockSizeInBytes = 16;

	private readonly ref GHashKey _key;
	private Vector128<byte> _accumulator;

	private GHash(ref GHashKey key)
	{
		_key = ref key;
		_accumulator = default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static long GetPaddedLength(int length)
	{
		return (long)length + BlockSizeInBytes - 1 & -BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static GHash Create(ref GHashKey key)
	{
		return new GHash(ref key);
	}

	public void Dispose()
	{
		_accumulator.ZeroMemory();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_accumulator = default;
	}

	// Appends one independently padded segment to the keyed state.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void AppendPaddedSegment(scoped ReadOnlySpan<byte> source)
	{
		AppendPaddedSegments(ref _accumulator, ref _key, source, default, default);
	}

	// Hashes three independently padded segments and resets the keyed state.
	internal int HashPaddedSegmentsAndReset(scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third, scoped Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSizeInBytes, nameof(destination));
		AppendPaddedSegments(ref _accumulator, ref _key, first, second, third);
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
	private static void AppendPaddedSegments(ref Vector128<byte> accumulator, ref GHashKey key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
	{
		if (GHashX86.IsSupported)
		{
			GHashX86.AppendPaddedSegments(ref accumulator, ref key, first, second, third);
		}
		else if (GHashArm.IsSupported)
		{
			GHashArm.AppendPaddedSegments(ref accumulator, in key.Value, first, second, third);
		}
		else
		{
			GHashSoftware.AppendPaddedSegments(ref accumulator, in key.Value, first, second, third);
		}
	}
}
