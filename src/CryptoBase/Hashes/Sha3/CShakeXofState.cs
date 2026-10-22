namespace CryptoBase.Hashes.Sha3;

// The IXof contract over CShakeSponge, shared by CShake128Xof and CShake256Xof, which check disposal before calling in.
// Resets return to the seed, so they keep the function name and customization string.
internal struct CShakeXofState<TRate> where TRate : IKeccakRate
{
	private CShakeSponge<TRate> _sponge;
	private bool _reading;

	internal void Initialize(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		_sponge.Initialize(functionName, customization);
		_reading = false;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Unsafe.SkipInit(out KeccakSponge<TRate> sponge);
		byte domainSeparator = CShakeSponge<TRate>.Initialize(ref sponge, functionName, customization);
		sponge.Absorb(source);
		sponge.Pad(domainSeparator);
		sponge.Squeeze(destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		ThrowHelper.ThrowIfXofReading(_reading);
		_sponge.Absorb(source);
	}

	internal void Read(Span<byte> destination)
	{
		if (destination.IsEmpty)
		{
			return;
		}

		if (!_reading)
		{
			_sponge.Pad();
			_reading = true;
		}

		_sponge.Squeeze(destination);
	}

	internal readonly void GetCurrentHash(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_reading);
		_sponge.SqueezeCopy(destination);
	}

	internal void GetHashAndReset(Span<byte> destination)
	{
		ThrowHelper.ThrowIfXofReading(_reading);

		_sponge.Pad();
		_sponge.Squeeze(destination);
		_sponge.Reset();
	}

	internal void Reset()
	{
		_sponge.Reset();
		_reading = false;
	}
}
