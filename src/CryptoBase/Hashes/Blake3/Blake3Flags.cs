namespace CryptoBase.Hashes.Blake3;

internal static class Blake3Flags
{
	internal const uint ChunkStart = 1 << 0;
	internal const uint ChunkEnd = 1 << 1;
	internal const uint Parent = 1 << 2;
	internal const uint Root = 1 << 3;
	internal const uint KeyedHash = 1 << 4;
	internal const uint DeriveKeyContext = 1 << 5;
	internal const uint DeriveKeyMaterial = 1 << 6;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool IsSecret(uint flags)
	{
		return (flags & (KeyedHash | DeriveKeyMaterial)) is not 0;
	}
}
