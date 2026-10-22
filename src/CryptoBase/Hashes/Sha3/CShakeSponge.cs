namespace CryptoBase.Hashes.Sha3;

// cSHAKE of SP 800-185, Sec. 3.3, over KeccakSponge. The seed is the state once the prefix has been absorbed: the bytepadded function name
// and customization string, followed for KMAC (Sec. 4.3) by the bytepadded key, so that a reset only copies it back.
// One-shot computations need no seed, so the static members run the same steps on a lone sponge.
internal struct CShakeSponge<TRate> where TRate : IKeccakRate
{
	private KeccakSponge<TRate> _seed;
	private KeccakSponge<TRate> _sponge;
	private byte _domainSeparator;

	internal readonly bool IsSqueezing => _sponge.IsSqueezing;

	internal void Initialize(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		_domainSeparator = Initialize(ref _sponge, functionName, customization);
		_seed = _sponge;
	}

	internal void InitializeKmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization)
	{
		_domainSeparator = Initialize(ref _sponge, "KMAC"u8, customization);
		AbsorbBytePaddedString(ref _sponge, key);
		_seed = _sponge;
	}

	// Makes the bytepadded string part of the seed.
	internal void AbsorbBytePaddedString(ReadOnlySpan<byte> value)
	{
		Debug.Assert(_domainSeparator is KeccakDomainSeparator.CShake);

		AbsorbBytePaddedString(ref _sponge, value);
		_seed = _sponge;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Absorb(ReadOnlySpan<byte> source)
	{
		_sponge.Absorb(source);
	}

	internal void AbsorbRightEncode(ulong value)
	{
		AbsorbRightEncode(ref _sponge, value);
	}

	internal void Pad()
	{
		_sponge.Pad(_domainSeparator);
	}

	internal void Squeeze(Span<byte> destination)
	{
		_sponge.Squeeze(destination);
	}

	// Copies only the sponge, since the seed plays no part in the output.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal readonly void SqueezeCopy(Span<byte> destination)
	{
		KeccakSponge<TRate> sponge = _sponge;
		sponge.Pad(_domainSeparator);
		sponge.Squeeze(destination);
	}

	// Right-encodes value first, as KMAC does with its output length. The copy holds the key, so it is erased.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal readonly void SqueezeCopy(ulong value, Span<byte> destination)
	{
		KeccakSponge<TRate> sponge = _sponge;

		try
		{
			AbsorbRightEncode(ref sponge, value);
			sponge.Pad(_domainSeparator);
			sponge.Squeeze(destination);
		}
		finally
		{
			sponge.ZeroMemory();
		}
	}

	internal void Reset()
	{
		_sponge = _seed;
	}

	// Erases both states, since a KMAC seed holds the key; Initialize must run again before any other use.
	internal void ZeroMemory()
	{
		_seed.ZeroMemory();
		_sponge.ZeroMemory();
		_domainSeparator = 0;
	}

	// With both strings empty, cSHAKE is SHAKE (Sec. 3.3): no prefix, and SHAKE's domain separator. Returns the domain separator to pad with.
	internal static byte Initialize(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		sponge.Reset();

		if (functionName.IsEmpty && customization.IsEmpty)
		{
			return KeccakDomainSeparator.Shake;
		}

		AbsorbPrefix(ref sponge, functionName, customization);
		return KeccakDomainSeparator.CShake;
	}

	// Absorbs bytepad(encode_string(value), rate), as KMAC does with its key right after Initialize.
	internal static void AbsorbBytePaddedString(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> value)
	{
		AbsorbBytePadHeader(ref sponge, value.Length);
		sponge.Absorb(value);
		sponge.FinishBlock();
	}

	internal static void AbsorbRightEncode(ref KeccakSponge<TRate> sponge, ulong value)
	{
		sponge.AbsorbWord(Sp800_185Encoding.RightEncode(value), Sp800_185Encoding.EncodedLength(value));
	}

	// bytepad(encode_string(N) || encode_string(S), rate); out of line so that one-shot callers inline the input and output steps instead.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void AbsorbPrefix(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		AbsorbBytePadHeader(ref sponge, functionName.Length);
		sponge.Absorb(functionName);
		AbsorbEncodedString(ref sponge, customization);
		sponge.FinishBlock();
	}

	// left_encode(rate), with which bytepad starts, then left_encode of the length in bits of the string that follows, with which its
	// encode_string starts. The rate takes 2 bytes and the length of a span at most 6, so one word holds both.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AbsorbBytePadHeader(ref KeccakSponge<TRate> sponge, int stringLength)
	{
		ulong rate = (ulong)TRate.RateInBytes;
		ulong bitLength = (ulong)stringLength * 8;
		int rateBytes = Sp800_185Encoding.EncodedLength(rate);
		int lengthBytes = Sp800_185Encoding.EncodedLength(bitLength);
		Debug.Assert(rateBytes + lengthBytes <= sizeof(ulong));

		sponge.AbsorbWord(Sp800_185Encoding.LeftEncode(rate) | Sp800_185Encoding.LeftEncode(bitLength) << rateBytes * 8, rateBytes + lengthBytes);
	}

	// encode_string of Sec. 2.3.2: the length in bits, left-encoded, then the string.
	private static void AbsorbEncodedString(ref KeccakSponge<TRate> sponge, ReadOnlySpan<byte> value)
	{
		ulong bitLength = (ulong)value.Length * 8;
		sponge.AbsorbWord(Sp800_185Encoding.LeftEncode(bitLength), Sp800_185Encoding.EncodedLength(bitLength));
		sponge.Absorb(value);
	}
}
