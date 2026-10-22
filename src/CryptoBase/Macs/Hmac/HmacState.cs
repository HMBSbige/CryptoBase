using CryptoBase.Hashes.Blake2b;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;

namespace CryptoBase.Macs.Hmac;

internal struct HmacState<TCore> where TCore : unmanaged, IHmacHashCore<TCore>
{
	private const byte Ipad = 0x36;
	private const byte Opad = 0x5c;

	// ARM64 SHA1 and SHA256 keep the in-place XorPad path after measured regressions.
	private static bool UseDirectKeyPads
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => Vector128.IsHardwareAccelerated
				&& TCore.HmacBlockSize % 32 is 0
				&& (!AdvSimd.Arm64.IsSupported || typeof(TCore) != typeof(Sha1Core) && typeof(TCore) != typeof(Sha256Core));
	}

	private TCore _innerSeed;
	private TCore _outerSeed;
	private TCore _innerState;

	[SkipLocalsInit]
	internal void Initialize(ReadOnlySpan<byte> key, bool reuseSeeds)
	{
		using CryptoBuffer<byte> keyBlock = new(stackalloc byte[TCore.HmacBlockSize + (UseDirectKeyPads ? TCore.HashLength : 0)]);

		if (UseDirectKeyPads)
		{
			ReadOnlySpan<byte> normalizedKey = NormalizeKeyForDirectPads(key, keyBlock.Span.Slice(TCore.HmacBlockSize));
			InitializeSeeds(normalizedKey, keyBlock.Span.Slice(0, TCore.HmacBlockSize), out _innerSeed, out _outerSeed);
		}
		else
		{
			NormalizeKey(key, keyBlock.Span);
			InitializeSeeds(keyBlock.Span, out _innerSeed, out _outerSeed);
		}

		if (reuseSeeds)
		{
			PrecompressKeyBlock(ref _innerSeed);
			PrecompressKeyBlock(ref _outerSeed);
		}

		_innerState = _innerSeed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PrecompressKeyBlock(ref TCore seed)
	{
		if (typeof(TCore) == typeof(Blake2b512Core))
		{
			Unsafe.As<TCore, Blake2b512Core>(ref seed).PrecompressBuffer();
		}
		else if (typeof(TCore) == typeof(Blake2b256Core))
		{
			Unsafe.As<TCore, Blake2b256Core>(ref seed).PrecompressBuffer();
		}
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
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal readonly int GetCurrentMac(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		TCore inner = _innerState;
		TCore outer = _outerSeed;

		try
		{
			return FinalizeMac(ref inner, ref outer, destination);
		}
		finally
		{
			inner.ZeroMemory();
			outer.ZeroMemory();
		}
	}

	internal int GetMacAndReset(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));
		return Vector128.IsHardwareAccelerated
			? GetMacAndResetDestructive(destination)
			: GetMacAndResetSoftware(destination);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private int GetMacAndResetSoftware(Span<byte> destination)
	{
		TCore inner = _innerState;
		TCore outer = _outerSeed;

		try
		{
			int written = FinalizeMac(ref inner, ref outer, destination);
			_innerState = _innerSeed;
			return written;
		}
		finally
		{
			inner.ZeroMemory();
			outer.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	internal int GetMacAndResetDestructive(Span<byte> destination)
	{
		Debug.Assert(destination.Length >= TCore.HashLength);

		TCore outer = _outerSeed;

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
		Debug.Assert(destination.Length >= TCore.HashLength);
		return FinalizeMac(ref _innerState, ref _outerSeed, destination);
	}

	[SkipLocalsInit]
	internal static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		Unsafe.SkipInit(out TCore inner);
		Unsafe.SkipInit(out TCore outer);
		Span<byte> keyBlock = stackalloc byte[TCore.HmacBlockSize + (UseDirectKeyPads ? TCore.HashLength : 0)];

		try
		{
			if (UseDirectKeyPads)
			{
				ReadOnlySpan<byte> normalizedKey = NormalizeKeyForDirectPads(key, keyBlock.Slice(TCore.HmacBlockSize));
				InitializeSeeds(normalizedKey, keyBlock.Slice(0, TCore.HmacBlockSize), out inner, out outer);
			}
			else
			{
				NormalizeKey(key, keyBlock);
				InitializeSeeds(keyBlock, out inner, out outer);
			}

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

	private static void InitializeSeeds(Span<byte> keyBlock, out TCore innerSeed, out TCore outerSeed)
	{
		XorPad(keyBlock, Ipad);
		innerSeed = TCore.Create();
		innerSeed.Append(keyBlock);

		XorPad(keyBlock, Ipad ^ Opad);
		outerSeed = TCore.Create();
		outerSeed.Append(keyBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int FinalizeMac(ref TCore inner, ref TCore outer, Span<byte> destination)
	{
		inner.Finalize(destination);
		outer.Append(destination.Slice(0, TCore.HashLength));
		outer.Finalize(destination);
		return TCore.HashLength;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void NormalizeKey(ReadOnlySpan<byte> key, Span<byte> keyBlock)
	{
		int normalizedKeyLength;

		if (key.Length > keyBlock.Length)
		{
			Unsafe.SkipInit(out TCore hash);

			try
			{
				hash = TCore.Create();
				hash.Append(key);
				hash.Finalize(keyBlock);
				normalizedKeyLength = TCore.HashLength;
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
	private static void InitializeSeeds(ReadOnlySpan<byte> key, Span<byte> keyBlock, out TCore innerSeed, out TCore outerSeed)
	{
		WritePaddedKey(key, keyBlock, Ipad);
		innerSeed = TCore.Create();
		innerSeed.Append(keyBlock);

		WritePaddedKey(key, keyBlock, Opad);
		outerSeed = TCore.Create();
		outerSeed.Append(keyBlock);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ReadOnlySpan<byte> NormalizeKeyForDirectPads(ReadOnlySpan<byte> key, Span<byte> hashBuffer)
	{
		if (key.Length <= TCore.HmacBlockSize)
		{
			return key;
		}

		Unsafe.SkipInit(out TCore hash);

		try
		{
			hash = TCore.Create();
			hash.Append(key);
			hash.Finalize(hashBuffer);
			return hashBuffer.Slice(0, TCore.HashLength);
		}
		finally
		{
			hash.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WritePaddedKey(ReadOnlySpan<byte> key, Span<byte> keyBlock, byte pad)
	{
		Debug.Assert(key.Length <= keyBlock.Length && keyBlock.Length % 32 is 0);

		ref byte keyReference = ref MemoryMarshal.GetReference(key);
		ref byte blockReference = ref MemoryMarshal.GetReference(keyBlock);
		Vector128<byte> padding = Vector128.Create(pad);

		for (int offset = 0; offset < keyBlock.Length; offset += 32)
		{
			Vector128<byte> low = LoadKeyPart(ref keyReference, key.Length, offset) ^ padding;
			Vector128<byte> high = LoadKeyPart(ref keyReference, key.Length, offset + 16) ^ padding;

			if (Vector256.IsHardwareAccelerated)
			{
				Vector256.Create(low, high).StoreUnsafe(ref blockReference, (nuint)offset);
			}
			else
			{
				low.StoreUnsafe(ref blockReference, (nuint)offset);
				high.StoreUnsafe(ref blockReference, (nuint)(offset + 16));
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> LoadKeyPart(ref byte key, int length, int offset)
	{
		int remaining = length - offset;

		if (remaining >= 16)
		{
			return Vector128.LoadUnsafe(ref key, (nuint)offset);
		}

		return remaining > 0 ? Vector128.LoadPartialUnsafe(ref key, (nuint)offset, remaining) : Vector128<byte>.Zero;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void XorPad(Span<byte> pad, byte value)
	{
		int length = TCore.HmacBlockSize;
		Debug.Assert(pad.Length == length);
		ref byte padReference = ref MemoryMarshal.GetReference(pad);
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
