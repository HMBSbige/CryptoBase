namespace CryptoBase.Internal;

internal static class CipherBufferGuard
{
	public static void Blocks(ReadOnlySpan<byte> source, Span<byte> destination, int blockSize)
	{
		if (source.Length % blockSize is not 0)
		{
			throw new ArgumentException("Source length must be a multiple of the block size.", nameof(source));
		}

		Output(source, destination);
	}

	public static void Output(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		SourceDestinationOverlap(source, destination.Slice(0, source.Length));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SourceDestinationOverlap(ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination)
	{
		if (source.Overlaps(destination, out int offset) && offset is not 0)
		{
			ThrowHelper.ThrowSourceDestinationOverlap(nameof(destination));
		}
	}
}
