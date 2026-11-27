namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHA3-512 hash core.
/// </summary>
/// <remarks>
/// Computes SHA3-512 as specified in FIPS 202.
/// HMAC uses the 72-byte sponge rate as its block size, per FIPS 202, Table 3.
/// </remarks>
public struct Sha3_512Core : IHmacHashCore<Sha3_512Core>
{
	private const int HashSizeInBytes = 64;

	private KeccakSponge<KeccakRate72> _sponge;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => KeccakRate72.RateInBytes;

	/// <inheritdoc />
	public static void Initialize(out Sha3_512Core core)
	{
		core = default;
	}

	// The one-shot computation for HashAlgorithm<TCore>.HashData, whose destination is already checked.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		KeccakSponge<KeccakRate72>.HashData(source, destination.Slice(0, HashSizeInBytes), KeccakDomainSeparator.Sha3);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	/// <inheritdoc />
	public void Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_sponge.Pad(KeccakDomainSeparator.Sha3);
		_sponge.Squeeze(destination.Slice(0, HashSizeInBytes));
	}
}
