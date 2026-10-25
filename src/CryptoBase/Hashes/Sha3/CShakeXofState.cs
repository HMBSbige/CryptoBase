namespace CryptoBase.Hashes.Sha3;

// The IXof contract over CShakeSponge, shared by CShake128Xof and CShake256Xof, which check disposal before calling in.
// Resets return to the seed, so they keep the function name and customization string, and the sponge squeezes only while reading.
internal struct CShakeXofState<TRate> where TRate : IKeccakRate
{
	private CShakeSponge<TRate> _sponge;

	internal void Initialize(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		_sponge.Initialize(functionName, customization);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		// With both strings empty, cSHAKE is SHAKE (SP 800-185, Sec. 3.3).
		if (functionName.IsEmpty && customization.IsEmpty)
		{
			KeccakSponge<TRate>.HashData(source, destination, KeccakDomainSeparator.Shake);
			return;
		}

		Unsafe.SkipInit(out KeccakSponge<TRate> sponge);
		byte domainSeparator = CShakeSponge<TRate>.Initialize(ref sponge, functionName, customization);
		sponge.Absorb(source);
		sponge.Pad(domainSeparator);
		sponge.Squeeze(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		ThrowHelper.ThrowIfXofReading(_sponge.IsSqueezing);
		_sponge.Absorb(source);
	}

	internal void Read(Span<byte> destination)
	{
		if (destination.IsEmpty)
		{
			return;
		}

		if (!_sponge.IsSqueezing)
		{
			_sponge.Pad();
		}

		_sponge.Squeeze(destination);
	}

	internal readonly void GetCurrentHash(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_sponge.IsSqueezing);
		_sponge.SqueezeCopy(destination);
	}

	internal void GetHashAndReset(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_sponge.IsSqueezing);

		_sponge.Pad();
		_sponge.Squeeze(destination);
		_sponge.Reset();
	}

	internal void Reset()
	{
		_sponge.Reset();
	}
}
