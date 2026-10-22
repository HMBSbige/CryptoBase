namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides the SHAKE128 extendable-output function core.
/// </summary>
/// <remarks>
/// Computes SHAKE128 as specified in FIPS 202, Sec. 6.2, over a 168-byte sponge rate. Use it through <see cref="Xof{TCore}" />, whose output length
/// is the destination length; collision resistance reaches its full 128 bits from 32 bytes of output, per FIPS 202, Table 4.
/// </remarks>
public struct Shake128Core : IXofCore<Shake128Core>
{
	private KeccakSponge<KeccakRate168> _sponge;

	[SkipLocalsInit]
	static Shake128Core IXofCore<Shake128Core>.Create()
	{
		Unsafe.SkipInit(out Shake128Core xof);
		xof._sponge.Reset();
		return xof;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IXofCore<Shake128Core>.Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	void IXofCore<Shake128Core>.Read(Span<byte> destination)
	{
		if (!_sponge.IsSqueezing)
		{
			_sponge.Pad(KeccakDomainSeparator.Shake);
		}

		_sponge.Squeeze(destination);
	}
}
