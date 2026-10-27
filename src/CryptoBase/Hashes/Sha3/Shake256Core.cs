namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHAKE256 extendable-output function core.
/// </summary>
/// <remarks>
/// Computes SHAKE256 as specified in FIPS 202, Sec. 6.2, over a 136-byte sponge rate. Use it through <see cref="Xof{TCore}" />, whose output length is the destination length; collision resistance reaches its full 256 bits from 64 bytes of output, per FIPS 202, Table 4.
/// </remarks>
public struct Shake256Core : IXofCore<Shake256Core>
{
	private KeccakSponge<KeccakRate136> _sponge;

	static Shake256Core IXofCore<Shake256Core>.Create()
	{
		return default;
	}

	// The one-shot computation for Xof<TCore>.HashData.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		KeccakSponge<KeccakRate136>.HashData(source, destination, KeccakDomainSeparator.Shake);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IXofCore<Shake256Core>.Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	void IXofCore<Shake256Core>.Read(Span<byte> destination)
	{
		if (!_sponge.IsSqueezing)
		{
			_sponge.Pad(KeccakDomainSeparator.Shake);
		}

		_sponge.Squeeze(destination);
	}
}
