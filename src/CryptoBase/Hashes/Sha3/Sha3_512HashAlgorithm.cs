namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHA3-512 hash core.
/// </summary>
/// <remarks>Computes SHA3-512 as specified in FIPS 202. HMAC uses the 72-byte sponge rate as its block size, per FIPS 202, Table 3.</remarks>
public struct Sha3_512HashAlgorithm : IHmacHashCore<Sha3_512HashAlgorithm>
{
	private const int HashSizeInBytes = 64;

	private KeccakSponge<KeccakRate72> _sponge;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => KeccakRate72.RateInBytes;

	[SkipLocalsInit]
	static Sha3_512HashAlgorithm IHashCore<Sha3_512HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Sha3_512HashAlgorithm hashAlgorithm);
		hashAlgorithm._sponge.Reset();
		return hashAlgorithm;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_sponge.Pad(KeccakDomainSeparator.Sha3);
		_sponge.Squeeze(destination.Slice(0, HashSizeInBytes));
	}
}
