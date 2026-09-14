namespace CryptoBase.Macs.Hmac;

internal struct HmacState<THash> where THash : unmanaged, IHmacHashCore<THash>
{
	private const byte Ipad = 0x36;
	private const byte Opad = 0x5c;

	private THash _innerSeed;
	private THash _outerSeed;
	private THash _innerState;

	[SkipLocalsInit]
	internal void Initialize(ReadOnlySpan<byte> key)
	{
		using CryptoBuffer<byte> keyBlock = new(stackalloc byte[THash.HmacBlockSize]);
		NormalizeKey(key, keyBlock.Span);
		InitializeSeeds(keyBlock.Span, out _innerSeed, out _outerSeed);
		_innerState = _innerSeed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Append(ReadOnlySpan<byte> source)
	{
		_innerState.Append(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void Reset()
	{
		_innerState.ZeroMemory();
		_innerState = _innerSeed;
	}

	[SkipLocalsInit]
	internal readonly int GetCurrentMac(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, THash.HashLength, nameof(destination));

		Span<byte> mac = stackalloc byte[THash.HashLength];
		THash inner = _innerState;
		THash outer = _outerSeed;

		try
		{
			int written = FinalizeMac(ref inner, ref outer, mac);
			mac.CopyTo(destination);
			return written;
		}
		finally
		{
			mac.ZeroMemory();
			inner.ZeroMemory();
			outer.ZeroMemory();
		}
	}

	internal int GetMacAndReset(Span<byte> destination)
	{
		int written = GetCurrentMac(destination);
		Reset();
		return written;
	}

	[SkipLocalsInit]
	internal int GetMacAndResetDestructive(Span<byte> destination)
	{
		Debug.Assert(destination.Length >= THash.HashLength);

		THash outer = _outerSeed;

		try
		{
			int written = FinalizeMac(ref _innerState, ref outer, destination);
			_innerState = _innerSeed;
			return written;
		}
		finally
		{
			outer.ZeroMemory();
		}
	}

	internal int GetMacDestructive(Span<byte> destination)
	{
		Debug.Assert(destination.Length >= THash.HashLength);
		return FinalizeMac(ref _innerState, ref _outerSeed, destination);
	}

	[SkipLocalsInit]
	internal static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, THash.HashLength, nameof(destination));

		using CryptoBuffer<byte> mac = new(stackalloc byte[THash.HashLength]);
		int written = MacCore(key, source, mac.Span);
		mac.Span.CopyTo(destination);
		return written;
	}

	internal static int MacDestructive(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Debug.Assert(destination.Length >= THash.HashLength);
		return MacCore(key, source, destination);
	}

	[SkipLocalsInit]
	private static int MacCore(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Unsafe.SkipInit(out THash inner);
		Unsafe.SkipInit(out THash outer);
		Span<byte> keyBlock = stackalloc byte[THash.HmacBlockSize];

		try
		{
			NormalizeKey(key, keyBlock);
			InitializeSeeds(keyBlock, out inner, out outer);
			inner.Append(source);
			return FinalizeMac(ref inner, ref outer, destination);
		}
		finally
		{
			keyBlock.ZeroMemory();
			inner.ZeroMemory();
			outer.ZeroMemory();
		}
	}

	private static void InitializeSeeds(Span<byte> keyBlock, out THash innerSeed, out THash outerSeed)
	{
		XorPad(keyBlock, Ipad);
		innerSeed = THash.Create();
		innerSeed.Append(keyBlock);

		XorPad(keyBlock, Ipad ^ Opad);
		outerSeed = THash.Create();
		outerSeed.Append(keyBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int FinalizeMac(ref THash inner, ref THash outer, Span<byte> destination)
	{
		inner.Finalize(destination);
		outer.Append(destination.Slice(0, THash.HashLength));
		outer.Finalize(destination);
		return THash.HashLength;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NormalizeKey(ReadOnlySpan<byte> key, Span<byte> keyBlock)
	{
		int normalizedKeyLength;

		if (key.Length > keyBlock.Length)
		{
			Unsafe.SkipInit(out THash hash);

			try
			{
				hash = THash.Create();
				hash.Append(key);
				hash.Finalize(keyBlock);
				normalizedKeyLength = THash.HashLength;
			}
			finally
			{
				hash.ZeroMemory();
			}
		}
		else
		{
			key.CopyTo(keyBlock);
			normalizedKeyLength = key.Length;
		}

		keyBlock.Slice(normalizedKeyLength).Clear();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorPad(Span<byte> pad, byte value)
	{
		int length = THash.HmacBlockSize;
		Debug.Assert(pad.Length == length);
		ref byte padReference = ref pad.GetReference();
		int offset = 0;

		if (Vector256.IsHardwareAccelerated)
		{
			Vector256<byte> mask = Vector256.Create(value);

			for (; offset <= length - Vector256<byte>.Count; offset += Vector256<byte>.Count)
			{
				(Vector256.LoadUnsafe(ref padReference, (nuint)offset) ^ mask).StoreUnsafe(ref padReference, (nuint)offset);
			}
		}

		ulong wordMask = value * 0x0101010101010101UL;

		for (; offset <= length - sizeof(ulong); offset += sizeof(ulong))
		{
			ref byte wordReference = ref Unsafe.Add(ref padReference, offset);
			ulong word = Unsafe.ReadUnaligned<ulong>(ref wordReference);
			Unsafe.WriteUnaligned(ref wordReference, word ^ wordMask);
		}

		for (; offset < length; ++offset)
		{
			Unsafe.Add(ref padReference, offset) ^= value;
		}
	}
}
