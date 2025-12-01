namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public sealed class Sm4Cipher : IBlock16Cipher<Sm4Cipher>
{
	public string Name => @"SM4";

	private readonly CryptoArrayPool<uint> _roundKeys;
	private readonly CryptoArrayPool<uint> _reverseRoundKeys;

	public void Dispose()
	{
		_roundKeys.Dispose();
		_reverseRoundKeys.Dispose();
	}

	public static bool IsSupported => true;

	public static BlockCryptoHardwareAcceleration HardwareAcceleration
	{
		get
		{
			BlockCryptoHardwareAcceleration result = BlockCryptoHardwareAcceleration.Unknown;

			if (AesX86.IsSupported)
			{
				if (Sse2.IsSupported && Ssse3.IsSupported)
				{
					result |= BlockCryptoHardwareAcceleration.Block4 | BlockCryptoHardwareAcceleration.Block8;
				}

				if (Avx2.IsSupported)
				{
					result |= BlockCryptoHardwareAcceleration.Block16;
				}
			}

			return result;
		}
	}

	private Sm4Cipher(in ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 16, nameof(key));

		_roundKeys = new CryptoArrayPool<uint>(32);
		_reverseRoundKeys = new CryptoArrayPool<uint>(32);

		Span<uint> rk = _roundKeys.Span;
		Span<uint> rrk = _reverseRoundKeys.Span;

		SM4Utils.InitRoundKeys(key, rk);

		rk.CopyTo(rrk);
		rrk.Reverse();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Sm4Cipher Create(in ReadOnlySpan<byte> key)
	{
		return new Sm4Cipher(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		Span<uint> rk = _roundKeys.Span;
		return SM4Utils.ProcessBlock(rk, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		Span<uint> rk = _reverseRoundKeys.Span;
		return SM4Utils.ProcessBlock(rk, source);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Encrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Decrypt(scoped in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			Span<uint> rk = _roundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			Span<uint> rk = _reverseRoundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Encrypt(scoped in VectorBuffer128 source)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			Span<uint> rk = _roundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Decrypt(scoped in VectorBuffer128 source)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			Span<uint> rk = _reverseRoundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 Encrypt(scoped in VectorBuffer256 source)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			Span<uint> rk = _roundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 Decrypt(scoped in VectorBuffer256 source)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			Span<uint> rk = _reverseRoundKeys.Span;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer256 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 Encrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 Decrypt(scoped in VectorBuffer512 source)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}
}
