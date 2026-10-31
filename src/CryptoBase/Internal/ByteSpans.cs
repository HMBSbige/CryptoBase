namespace CryptoBase.Internal;

internal static class ByteSpans
{
	/// <summary>
	/// Gets the result of <see cref="MemoryExtensions.Overlaps{T}(ReadOnlySpan{T}, ReadOnlySpan{T})" /> for bytes, which the JIT does not always inline.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool Overlaps(ReadOnlySpan<byte> span, ReadOnlySpan<byte> other)
	{
		if (span.IsEmpty || other.IsEmpty)
		{
			return false;
		}

		// Spans overlap when other starts from other.Length - 1 bytes before span to span.Length - 1 bytes after it. Shifting that range to start at zero checks both ends with one unsigned comparison, which matches (nuint)byteOffset < (nuint)span.Length || (nuint)byteOffset > (nuint)(-(nint)other.Length).
		nint byteOffset = Unsafe.ByteOffset(ref MemoryMarshal.GetReference(span), ref MemoryMarshal.GetReference(other));
		return (nuint)(byteOffset + other.Length - 1) < (nuint)span.Length + (nuint)other.Length - 1;
	}
}
