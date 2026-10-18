namespace CryptoBase.Internal.Extensions;

internal static class Vector512CreationExtensions
{
	extension(Vector512)
	{
		// Requires AVX-512F. One shuffle copies the initialized low 128 bits to every block; Vector512.Create(Vector128<T>) takes three inserts on .NET 10, two of them into an uninitialized vector read from the stack.
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector512<T> Broadcast<T>(Vector128<T> value) where T : unmanaged
		{
			Vector512<uint> wide = value.AsUInt32().ToVector256Unsafe().ToVector512Unsafe();
			return Avx512F.Shuffle4x128(wide, wide, 0).As<uint, T>();
		}
	}
}
