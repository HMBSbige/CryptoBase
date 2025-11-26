namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public sealed class SM4Crypto : BlockCrypto16
{
	public override string Name => @"SM4";

	public override BlockCryptoHardwareAcceleration HardwareAcceleration
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

	private readonly CryptoArrayPool<uint> _roundKeys;
	private readonly CryptoArrayPool<uint> _reverseRoundKeys;

	public SM4Crypto(ReadOnlySpan<byte> key)
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

	public override void Dispose()
	{
		_roundKeys.Dispose();
		_reverseRoundKeys.Dispose();

		base.Dispose();
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		Span<uint> rk = _roundKeys.Span;

		Unsafe.WriteUnaligned(ref destination.GetReference(), SM4Utils.Encrypt(rk, source.AsVectorBuffer16()));
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Span<uint> rk = _reverseRoundKeys.Span;

		Unsafe.WriteUnaligned(ref destination.GetReference(), SM4Utils.Encrypt(rk, source.AsVectorBuffer16()));
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			SM4Utils.Encrypt4(_roundKeys.Span, source, destination);
		}
		else
		{
			base.Encrypt4(source, destination);
		}
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			SM4Utils.Encrypt4(_reverseRoundKeys.Span, source, destination);
		}
		else
		{
			base.Decrypt4(source, destination);
		}
	}

	public override void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			SM4Utils.Encrypt8(_roundKeys.Span, source, destination);
		}
		else
		{
			base.Encrypt8(source, destination);
		}
	}

	public override void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
		{
			SM4Utils.Encrypt8(_reverseRoundKeys.Span, source, destination);
		}
		else
		{
			base.Decrypt8(source, destination);
		}
	}

	public override void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			SM4Utils.Encrypt16(_roundKeys.Span, source, destination);
		}
		else
		{
			base.Encrypt16(source, destination);
		}
	}

	public override void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (AesX86.IsSupported && Avx2.IsSupported)
		{
			SM4Utils.Encrypt16(_reverseRoundKeys.Span, source, destination);
		}
		else
		{
			base.Decrypt16(source, destination);
		}
	}
}
