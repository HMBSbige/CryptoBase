using CryptoBase.Hashes.Sha256;

namespace CryptoBase.Hashes.Sha224;

/// <summary>
/// Provides the SHA-224 hash core.
/// </summary>
public struct Sha224HashAlgorithm : IHmacHashCore<Sha224HashAlgorithm>
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

	private Sha256Core _state;

	/// <inheritdoc />
	public static int HashLengthInBytes => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSizeInBytes => Sha256Core.BlockSizeInBytes;

	[SkipLocalsInit]
	static Sha224HashAlgorithm IHashCore<Sha224HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Sha224HashAlgorithm hashAlgorithm);
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
