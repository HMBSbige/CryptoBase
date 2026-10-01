namespace CryptoBase.Internal.Extensions;

internal static class SpanReinterpretExtensions
{
	extension(ref byte reference)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T As<T>()
		{
			return ref Unsafe.As<byte, T>(ref reference);
		}
	}

	extension<T>(Span<T> span)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T GetReference()
		{
			return ref MemoryMarshal.GetReference(span);
		}
	}

	extension<T>(ReadOnlySpan<T> span)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T GetReference()
		{
			return ref MemoryMarshal.GetReference(span);
		}
	}
}
