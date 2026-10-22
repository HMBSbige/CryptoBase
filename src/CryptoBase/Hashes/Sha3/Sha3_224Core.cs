namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHA3-224 hash core.
/// </summary>
/// <remarks>Computes SHA3-224 as specified in FIPS 202. HMAC uses the 144-byte sponge rate as its block size, per FIPS 202, Table 3.</remarks>
public struct Sha3_224Core : IHmacHashCore<Sha3_224Core>
{
	private const int HashSizeInBytes = 28;

	private KeccakSponge<KeccakRate144> _sponge;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => KeccakRate144.RateInBytes;

	[SkipLocalsInit]
	static Sha3_224Core IHashCore<Sha3_224Core>.Create()
	{
		Unsafe.SkipInit(out Sha3_224Core hashAlgorithm);
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
