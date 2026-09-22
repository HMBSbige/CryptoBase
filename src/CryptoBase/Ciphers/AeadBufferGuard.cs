namespace CryptoBase.Ciphers;

internal static class AeadBufferGuard
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ValidateInput(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination, ReadOnlySpan<byte> tag, int nonceSize, int tagSize)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, nonceSize, nameof(nonce));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));
		ArgumentOutOfRangeException.ThrowIfNotEqual(tag.Length, tagSize, nameof(tag));

		destination = destination.Slice(0, source.Length);

		CipherBufferGuard.SourceDestinationOverlap(source, destination);

		if (tag.Overlaps(destination))
		{
			ThrowHelper.ThrowTagDestinationOverlap(nameof(tag));
		}
	}
}
