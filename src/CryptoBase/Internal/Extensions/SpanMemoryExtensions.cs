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

	extension<T>(Span<T> span) where T : unmanaged
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public void ZeroMemory()
		{
			CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(span));
		}
	}
}
