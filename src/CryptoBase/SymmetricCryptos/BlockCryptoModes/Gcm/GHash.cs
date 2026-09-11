namespace CryptoBase.SymmetricCryptos.BlockCryptoModes.Gcm;

internal struct GHash
{
	internal const int BlockSizeInBytes = 16;

	private VectorBuffer16 _key;
	private VectorBuffer16 _accumulator;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static long GetPaddedLength(int length)
	{
		return (long)length + BlockSizeInBytes - 1 & -BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static GHash Create(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, BlockSizeInBytes, nameof(key));
		return new GHash { _key = key.AsVectorBuffer16() };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_accumulator = default;
	}

	/// <summary>
	/// Appends one independently padded segment to the keyed state.
	/// </summary>
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void AppendPaddedSegment(ReadOnlySpan<byte> source)
	{
		AppendPaddedSegments(ref _accumulator, in _key, source, default, default);
	}

	/// <summary>
	/// Hashes three independently padded segments and resets the keyed state.
	/// </summary>
	internal int HashPaddedSegmentsAndReset(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSizeInBytes, nameof(destination));
		AppendPaddedSegments(ref _accumulator, in _key, first, second, third);
		WriteHash(in _accumulator, destination);
		Reset();
		return BlockSizeInBytes;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteHash(in VectorBuffer16 accumulator, Span<byte> destination)
	{
		ReadOnlySpan<byte> hash = accumulator;
		hash.CopyTo(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendPaddedSegments(ref VectorBuffer16 accumulator, in VectorBuffer16 key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
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
