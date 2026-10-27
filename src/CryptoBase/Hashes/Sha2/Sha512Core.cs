namespace CryptoBase.Hashes.Sha2;

/// <summary>
/// Provides the SHA-512 hash core.
/// </summary>
public struct Sha512Core : IHmacHashCore<Sha512Core>
{
	internal const int HashSizeInBytes = 64;
	private const ulong InitialH0 = 0x6A09E667F3BCC908UL;
	private const ulong InitialH1 = 0xBB67AE8584CAA73BUL;
	private const ulong InitialH2 = 0x3C6EF372FE94F82BUL;
	private const ulong InitialH3 = 0xA54FF53A5F1D36F1UL;
	private const ulong InitialH4 = 0x510E527FADE682D1UL;
	private const ulong InitialH5 = 0x9B05688C2B3E6C1FUL;
	private const ulong InitialH6 = 0x1F83D9ABFB41BD6BUL;
	private const ulong InitialH7 = 0x5BE0CD19137E2179UL;

	private Sha512State _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Sha512State.BlockSizeInBytes;

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Sha512Core IHashCore<Sha512Core>.Create()
	{
		Unsafe.SkipInit(out Sha512Core hashAlgorithm);
		hashAlgorithm._state.Reset(InitialH0, InitialH1, InitialH2, InitialH3, InitialH4, InitialH5, InitialH6, InitialH7);
		return hashAlgorithm;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state.Append(source);
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_state.Finalize(destination, HashLength);
	}
}
