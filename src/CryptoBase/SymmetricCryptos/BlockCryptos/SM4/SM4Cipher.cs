using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

/// <summary>
/// Implements the SM4 block cipher.
/// </summary>
public sealed class SM4Cipher : IBlock16Cipher<SM4Cipher>
{
	/// <inheritdoc />
	public string Name => @"SM4";

	private VectorBuffer128 _roundKeys;
	private VectorBuffer128 _reverseRoundKeys;

	private Span<uint> RoundKeys
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => MemoryMarshal.Cast<byte, uint>(_roundKeys.AsSpan());
	}

	private Span<uint> ReverseRoundKeys
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => MemoryMarshal.Cast<byte, uint>(_reverseRoundKeys.AsSpan());
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_roundKeys.ZeroMemory();
		_reverseRoundKeys.ZeroMemory();
	}

	/// <inheritdoc />
	public static bool IsSupported => true;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsX86Vector128Supported()
	{
		return AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsX86Vector256Supported()
	{
		return AesX86.IsSupported && Avx2.IsSupported;
	}

	/// <inheritdoc />
	public static BlockCipherHardwareAcceleration HardwareAcceleration
	{
		get
		{
			BlockCipherHardwareAcceleration result = BlockCipherHardwareAcceleration.Unknown;

			if (IsX86Vector128Supported())
			{
				result |= BlockCipherHardwareAcceleration.Block4 | BlockCipherHardwareAcceleration.Block8;
			}

			if (IsX86Vector256Supported())
			{
				result |= BlockCipherHardwareAcceleration.Block8V256 | BlockCipherHardwareAcceleration.Block16V256;
			}

			return result;
		}
	}

	private SM4Cipher(in ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 16, nameof(key));

		_roundKeys = default;
		_reverseRoundKeys = default;

		Span<uint> rk = RoundKeys;
		Span<uint> rrk = ReverseRoundKeys;

		SM4Utils.InitRoundKeys(key, rk);

		rk.CopyTo(rrk);
		rrk.Reverse();
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static SM4Cipher Create(in ReadOnlySpan<byte> key)
	{
		return new SM4Cipher(key);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(VectorBuffer16 source)
	{
		Span<uint> rk = RoundKeys;
		return SM4Utils.ProcessBlock(rk, source);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(VectorBuffer16 source)
	{
		Span<uint> rk = ReverseRoundKeys;
		return SM4Utils.ProcessBlock(rk, source);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Encrypt(in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Decrypt(in VectorBuffer32 source)
	{
		Unsafe.SkipInit(out VectorBuffer32 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Encrypt(in VectorBuffer64 source)
	{
		if (IsX86Vector128Supported())
		{
			Span<uint> rk = RoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Decrypt(in VectorBuffer64 source)
	{
		if (IsX86Vector128Supported())
		{
			Span<uint> rk = ReverseRoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer64 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Encrypt(in VectorBuffer128 source)
	{
		if (IsX86Vector128Supported())
		{
			Span<uint> rk = RoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Encrypt(source.Lower);
		r.Upper = Encrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Decrypt(in VectorBuffer128 source)
	{
		if (IsX86Vector128Supported())
		{
			Span<uint> rk = ReverseRoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.Lower = Decrypt(source.Lower);
		r.Upper = Decrypt(source.Upper);

		return r;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 EncryptV256(in VectorBuffer128 source)
	{
		if (IsX86Vector256Supported())
		{
			Span<uint> rk = RoundKeys;
			return SM4Utils.ProcessBlockAvx2(rk, source);
		}

		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 DecryptV256(in VectorBuffer128 source)
	{
		if (IsX86Vector256Supported())
		{
			Span<uint> rk = ReverseRoundKeys;
			return SM4Utils.ProcessBlockAvx2(rk, source);
		}

		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV256(in VectorBuffer256 source)
	{
		if (IsX86Vector256Supported())
		{
			Span<uint> rk = RoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV256(in VectorBuffer256 source)
	{
		if (IsX86Vector256Supported())
		{
			Span<uint> rk = ReverseRoundKeys;
			return SM4Utils.ProcessBlock(rk, source);
		}

		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV512(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV512(in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 EncryptV512(in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 DecryptV512(in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}
}
