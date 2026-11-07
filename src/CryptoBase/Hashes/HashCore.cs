namespace CryptoBase.Hashes;

// Calls the members of a hash core, which a core may implement explicitly, through the constraint, so that the core is not boxed.
internal static class HashCore
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static T Create<T>() where T : unmanaged, IHashCore<T>
	{
		return T.Create();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Append<T>(ref T core, ReadOnlySpan<byte> source) where T : unmanaged, IHashCore<T>
	{
		core.Append(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Finalize<T>(ref T core, Span<byte> destination) where T : unmanaged, IHashCore<T>
	{
		core.Finalize(destination);
	}
}
