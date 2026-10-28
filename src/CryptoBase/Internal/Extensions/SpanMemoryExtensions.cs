namespace CryptoBase.Internal.Extensions;

internal static class SpanMemoryExtensions
{
	extension<T>(ref T reference) where T : unmanaged, allows ref struct
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Span<byte> AsSpan()
		{
			return MemoryMarshal.CreateSpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ReadOnlySpan<byte> AsReadOnlySpan()
		{
			return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void ZeroMemory()
		{
			CryptographicOperations.ZeroMemory(reference.AsSpan());
		}
	}

	extension<T>(Span<T> span)
	{
		// Unlike the implicit conversion, which is not marked for aggressive inlining, this costs no inlining budget when reached through aggressive inlines alone, so it is less likely to stay a call in large methods, around which live vectors must be saved.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ReadOnlySpan<T> AsReadOnlySpan()
		{
			return MemoryMarshal.CreateReadOnlySpan(ref MemoryMarshal.GetReference(span), span.Length);
		}
	}

	extension<T>(Span<T> span) where T : unmanaged
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void ZeroMemory()
		{
			CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(span));
		}
	}
}
