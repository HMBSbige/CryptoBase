namespace CryptoBase.SymmetricCryptos;

internal static class AeadBufferGuard
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ValidateInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination, ReadOnlySpan<byte> tag, int nonceSize, int tagSize)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, nonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfNotEqual(destination.Length, source.Length, nameof(destination));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tag.Length, tagSize, nameof(tag));

		if (source.Overlaps(destination, out int elementOffset) && elementOffset is not 0)
		{
			ThrowHelper.ThrowSourceDestinationOverlap(nameof(destination));
		}

		if (tag.Overlaps(destination))
		{
			ThrowHelper.ThrowTagDestinationOverlap(nameof(tag));
		}
	}
}
