namespace CryptoBase.Internal.Extensions;

internal static class Vector512CreationExtensions
{
	extension(Vector512)
	{
		// Requires AVX-512F. Every output block selects the initialized low 128 bits.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector512<T> Broadcast<T>(Vector128<T> value) where T : unmanaged
		{
			Vector512<uint> wide = value.AsUInt32().ToVector256Unsafe().ToVector512Unsafe();
			return Avx512F.Shuffle4x128(wide, wide, 0).As<uint, T>();
		}
	}
}
