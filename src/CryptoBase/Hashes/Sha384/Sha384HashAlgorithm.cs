using CryptoBase.Hashes.Sha512;

namespace CryptoBase.Hashes.Sha384;

/// <summary>
/// Provides the SHA-384 hash core.
/// </summary>
public struct Sha384HashAlgorithm : IHmacHashCore<Sha384HashAlgorithm>
{
	private const int HashSizeInBytes = 48;
	private const ulong InitialH0 = 0xCBBB9D5DC1059ED8UL;
	private const ulong InitialH1 = 0x629A292A367CD507UL;
	private const ulong InitialH2 = 0x9159015A3070DD17UL;
	private const ulong InitialH3 = 0x152FECD8F70E5939UL;
	private const ulong InitialH4 = 0x67332667FFC00B31UL;
	private const ulong InitialH5 = 0x8EB44A8768581511UL;
	private const ulong InitialH6 = 0xDB0C2E0D64F98FA7UL;
	private const ulong InitialH7 = 0x47B5481DBEFA4FA4UL;

	private Sha512Core _state;

	/// <inheritdoc />
	public static int HashLengthInBytes => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSizeInBytes => Sha512Core.BlockSizeInBytes;

	[SkipLocalsInit]
	static Sha384HashAlgorithm IHashCore<Sha384HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Sha384HashAlgorithm hashAlgorithm);
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
