namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHA3-384 hash core.
/// </summary>
/// <remarks>Computes SHA3-384 as specified in FIPS 202. HMAC uses the 104-byte sponge rate as its block size, per FIPS 202, Table 3.</remarks>
public struct Sha3_384Core : IHmacHashCore<Sha3_384Core>
{
	private const int HashSizeInBytes = 48;

	private KeccakSponge<KeccakRate104> _sponge;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => KeccakRate104.RateInBytes;

	static Sha3_384Core IHashCore<Sha3_384Core>.Create()
	{
		return default;
	}

	// The one-shot computation for HashAlgorithm<TCore>.HashData, whose destination is already checked.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		KeccakSponge<KeccakRate104>.HashData(source, destination.Slice(0, HashSizeInBytes), KeccakDomainSeparator.Sha3);
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
