namespace CryptoBase.Hashes.Sha2;

/// <summary>
/// Provides the SHA-256 hash core.
/// </summary>
public struct Sha256Core : IHmacHashCore<Sha256Core>
{
	internal const int HashSizeInBytes = 32;
	private const uint InitialH0 = 0x6A09E667U;
	private const uint InitialH1 = 0xBB67AE85U;
	private const uint InitialH2 = 0x3C6EF372U;
	private const uint InitialH3 = 0xA54FF53AU;
	private const uint InitialH4 = 0x510E527FU;
	private const uint InitialH5 = 0x9B05688CU;
	private const uint InitialH6 = 0x1F83D9ABU;
	private const uint InitialH7 = 0x5BE0CD19U;

	private Sha256State _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Sha256State.BlockSizeInBytes;

	[SkipLocalsInit]
	static Sha256Core IHashCore<Sha256Core>.Create()
	{
		Unsafe.SkipInit(out Sha256Core hashAlgorithm);
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
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_state.Finalize(destination, HashLength);
	}
}
