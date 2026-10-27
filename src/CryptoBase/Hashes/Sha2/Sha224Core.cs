namespace CryptoBase.Hashes.Sha2;

/// <summary>
/// Provides the SHA-224 hash core.
/// </summary>
public struct Sha224Core : IHmacHashCore<Sha224Core>
{
	private const int HashSizeInBytes = 28;
	private const uint InitialH0 = 0xC1059ED8U;
	private const uint InitialH1 = 0x367CD507U;
	private const uint InitialH2 = 0x3070DD17U;
	private const uint InitialH3 = 0xF70E5939U;
	private const uint InitialH4 = 0xFFC00B31U;
	private const uint InitialH5 = 0x68581511U;
	private const uint InitialH6 = 0x64F98FA7U;
	private const uint InitialH7 = 0xBEFA4FA4U;

	private Sha256State _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Sha256State.BlockSizeInBytes;

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Sha224Core IHashCore<Sha224Core>.Create()
	{
		Unsafe.SkipInit(out Sha224Core hashAlgorithm);
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
