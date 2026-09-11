namespace CryptoBase.Hashes.Sha512;

/// <summary>
/// Provides the SHA-512 hash core.
/// </summary>
public struct Sha512HashAlgorithm : IHmacHashCore<Sha512HashAlgorithm>
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

	private Sha512Core _state;

	/// <inheritdoc />
	public static int HashLengthInBytes => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSizeInBytes => Sha512Core.BlockSizeInBytes;

	[SkipLocalsInit]
	static Sha512HashAlgorithm IHashCore<Sha512HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Sha512HashAlgorithm hashAlgorithm);
		hashAlgorithm.Reset();
		return hashAlgorithm;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state.Append(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Reset()
	{
		_state.Reset(InitialH0, InitialH1, InitialH2, InitialH3, InitialH4, InitialH5, InitialH6, InitialH7);
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLengthInBytes, nameof(destination));
		_state.Finalize(destination, HashLengthInBytes);
	}
}
