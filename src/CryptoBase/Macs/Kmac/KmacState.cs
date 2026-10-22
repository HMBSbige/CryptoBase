using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Macs.Kmac;

// KMAC of SP 800-185, Sec. 4.3, over CShakeSponge, shared by Kmac128Algorithm and Kmac256Algorithm, which check disposal before calling in.
// The seed holds the bytepadded key after the prefix of cSHAKE with the function name "KMAC", so resets keep the key and customization string.
// The output length L, in bits, is right-encoded after the message, so it must come from the destination rather than from truncating a longer output.
internal struct KmacState<TRate> where TRate : IKeccakRate
{
	private CShakeSponge<TRate> _sponge;

	internal void Initialize(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization)
	{
		Seed(ref _sponge, key, customization);
	}

	internal static void Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization)
	{
		ThrowIfEmpty(destination);
		Compute(key, source, customization, OutputLengthInBits(destination), destination);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	internal readonly void GetCurrentMac(Span<byte> destination)
	{
		ThrowIfEmpty(destination);
		_sponge.SqueezeCopy(OutputLengthInBits(destination), destination);
	}

	internal void GetMacAndReset(Span<byte> destination)
	{
		ThrowIfEmpty(destination);

		Finish(ref _sponge, OutputLengthInBits(destination), destination);
		_sponge.Reset();
	}

	internal void Reset()
	{
		_sponge.Reset();
	}

	internal void ZeroMemory()
	{
		_sponge.ZeroMemory();
	}

	// The steps below are shared with KmacXofState, which encodes L as 0 (Sec. 4.3.1).

	internal static void Seed(ref CShakeSponge<TRate> sponge, ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization)
	{
		sponge.InitializeKmac(key, customization);
	}

	internal static void Finish(ref CShakeSponge<TRate> sponge, ulong outputLengthInBits, Span<byte> destination)
	{
		sponge.AbsorbRightEncode(outputLengthInBits);
		sponge.Pad();
		sponge.Squeeze(destination);
	}

	// Seed and Finish on a lone sponge. All input is absorbed before the output is written, so the destination may overlap the key or the source.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, ReadOnlySpan<byte> customization, ulong outputLengthInBits, Span<byte> destination)
	{
		Unsafe.SkipInit(out KeccakSponge<TRate> sponge);

		try
		{
			byte domainSeparator = CShakeSponge<TRate>.Initialize(ref sponge, "KMAC"u8, customization);
			CShakeSponge<TRate>.AbsorbBytePaddedString(ref sponge, key);
			sponge.Absorb(source);
			CShakeSponge<TRate>.AbsorbRightEncode(ref sponge, outputLengthInBits);
			sponge.Pad(domainSeparator);
			sponge.Squeeze(destination);
		}
		finally
		{
			sponge.ZeroMemory();
		}
	}

	private static ulong OutputLengthInBits(Span<byte> destination)
	{
		return (ulong)destination.Length * 8;
	}

	// An empty tag would verify every message.
	private static void ThrowIfEmpty(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfZero(destination.Length, nameof(destination));
	}
}
