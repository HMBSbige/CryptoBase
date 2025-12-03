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

	public static BlockCipherHardwareAcceleration HardwareAcceleration
	{
		get
		{
			BlockCipherHardwareAcceleration result = BlockCipherHardwareAcceleration.Unknown;

			if (AesX86.IsSupported)
			{
				if (Sse2.IsSupported && Ssse3.IsSupported)
				{
					result |= BlockCipherHardwareAcceleration.Block4 | BlockCipherHardwareAcceleration.Block8;
				}

				if (Avx2.IsSupported)
				{
					result |= BlockCipherHardwareAcceleration.Block8V256 | BlockCipherHardwareAcceleration.Block16V256;
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 EncryptV256(scoped in VectorBuffer128 source)
	{
		Span<uint> rk = _roundKeys.Span;
		return SM4Utils.ProcessBlockAvx2(rk, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 DecryptV256(scoped in VectorBuffer128 source)
	{
		Span<uint> rk = _reverseRoundKeys.Span;
		return SM4Utils.ProcessBlockAvx2(rk, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV256(scoped in VectorBuffer256 source)
	{
		Span<uint> rk = _roundKeys.Span;
		return SM4Utils.ProcessBlock(rk, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV256(scoped in VectorBuffer256 source)
	{
		Span<uint> rk = _reverseRoundKeys.Span;
		return SM4Utils.ProcessBlock(rk, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 EncryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 DecryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}
}
