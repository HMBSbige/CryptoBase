namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHAKE128 extendable-output function core.
/// </summary>
/// <remarks>
/// Computes SHAKE128 as specified in FIPS 202, Sec. 6.2.
/// Each read fills its destination. Collision resistance reaches its full 128 bits from 32 bytes of output, per FIPS 202, Table 4.
/// </remarks>
public struct Shake128Core : IXofCore<Shake128Core>
{
	private KeccakSponge<KeccakRate168> _sponge;

	/// <inheritdoc />
	public static Shake128Core Create()
	{
		return default;
	}

	// The one-shot computation for Xof<TCore>.HashData.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		KeccakSponge<KeccakRate168>.HashData(source, destination, KeccakDomainSeparator.Shake);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	/// <inheritdoc />
	public void Read(Span<byte> destination)
	{
		if (!_sponge.IsSqueezing)
		{
			_sponge.Pad(KeccakDomainSeparator.Shake);
		}

		_sponge.Squeeze(destination);
	}
}
