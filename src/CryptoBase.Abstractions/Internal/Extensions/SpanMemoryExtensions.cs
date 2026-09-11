namespace CryptoBase.Abstractions.Internal.Extensions;

/// <summary>
/// Provides low-level span and memory-clearing extensions.
/// </summary>
internal static class SpanMemoryExtensions
{
	extension<T>(ref T reference) where T : unmanaged, allows ref struct
	{
		/// <summary>
		/// Creates a writable byte span over the referenced value.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Span<byte> AsSpan()
		{
			return MemoryMarshal.CreateSpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		/// <summary>
		/// Creates a read-only byte span over the referenced value.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ReadOnlySpan<byte> AsReadOnlySpan()
		{
			return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		/// <summary>
		/// Securely clears the referenced value.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void ZeroMemory()
		{
			CryptographicOperations.ZeroMemory(reference.AsSpan());
		}
	}

	extension<T>(Span<T> span) where T : unmanaged
	{
		/// <summary>
		/// Securely clears the span.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void ZeroMemory()
		{
			CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(span));
		}
	}
}
