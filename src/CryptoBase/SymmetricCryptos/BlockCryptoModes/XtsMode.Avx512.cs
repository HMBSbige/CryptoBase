namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Gf128Mul(in Vector512<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector512<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector512<ulong> tmp2 = Pclmulqdq.V512.CarrylessMultiply(tmp1, Vector512.Create(0x87UL), 0x01);

		tmp1 = Avx512BW.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetInitTweak16Avx512(in ReadOnlySpan<byte> tweakBuffer, in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref readonly Vector128<byte> x0 = ref Unsafe.As<byte, Vector128<byte>>(ref tweakBuffer.GetReference());
		ref Vector512<byte> tweak0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 0 * 64));
		ref Vector512<byte> tweak1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 1 * 64));
		ref Vector512<byte> tweak2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 2 * 64));
		ref Vector512<byte> tweak3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 3 * 64));

		Vector128<byte> x1 = Gf128Mul(x0);
		Vector128<byte> x2 = Gf128Mul(x0, 2);
		Vector128<byte> x3 = Gf128Mul(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		tweak0 = t;

		tweak1 = Gf128Mul(tweak0, 4);
		tweak2 = Gf128Mul(tweak0, 8);
		tweak3 = Gf128Mul(tweak0, 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul16Avx512(in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref Vector512<byte> tweak0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 0 * 64));
		ref Vector512<byte> tweak1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 1 * 64));
		ref Vector512<byte> tweak2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 2 * 64));
		ref Vector512<byte> tweak3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 3 * 64));

		tweak0 = Gf128Mul(tweak0, 16);
		tweak1 = Gf128Mul(tweak1, 16);
		tweak2 = Gf128Mul(tweak2, 16);
		tweak3 = Gf128Mul(tweak3, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetInitTweak32Avx512(in ReadOnlySpan<byte> tweakBuffer, in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref readonly Vector128<byte> x0 = ref Unsafe.As<byte, Vector128<byte>>(ref tweakBuffer.GetReference());
		ref Vector512<byte> tweak0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 0 * 64));
		ref Vector512<byte> tweak1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 1 * 64));
		ref Vector512<byte> tweak2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 2 * 64));
		ref Vector512<byte> tweak3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 3 * 64));
		ref Vector512<byte> tweak4 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 4 * 64));
		ref Vector512<byte> tweak5 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 5 * 64));
		ref Vector512<byte> tweak6 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 6 * 64));
		ref Vector512<byte> tweak7 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 7 * 64));

		Vector128<byte> x1 = Gf128Mul(x0);
		Vector128<byte> x2 = Gf128Mul(x0, 2);
		Vector128<byte> x3 = Gf128Mul(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		tweak0 = t;

		tweak1 = Gf128Mul(tweak0, 4);
		tweak2 = Gf128Mul(tweak0, 8);
		tweak3 = Gf128Mul(tweak0, 12);
		tweak4 = Gf128Mul(tweak0, 16);
		tweak5 = Gf128Mul(tweak0, 20);
		tweak6 = Gf128Mul(tweak0, 24);
		tweak7 = Gf128Mul(tweak0, 28);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul32Avx512(in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref Vector512<byte> tweak0 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 0 * 64));
		ref Vector512<byte> tweak1 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 1 * 64));
		ref Vector512<byte> tweak2 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 2 * 64));
		ref Vector512<byte> tweak3 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 3 * 64));
		ref Vector512<byte> tweak4 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 4 * 64));
		ref Vector512<byte> tweak5 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 5 * 64));
		ref Vector512<byte> tweak6 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 6 * 64));
		ref Vector512<byte> tweak7 = ref Unsafe.As<byte, Vector512<byte>>(ref Unsafe.Add(ref ptr, 7 * 64));

		tweak0 = Gf128Mul(tweak0, 32);
		tweak1 = Gf128Mul(tweak1, 32);
		tweak2 = Gf128Mul(tweak2, 32);
		tweak3 = Gf128Mul(tweak3, 32);
		tweak4 = Gf128Mul(tweak4, 32);
		tweak5 = Gf128Mul(tweak5, 32);
		tweak6 = Gf128Mul(tweak6, 32);
		tweak7 = Gf128Mul(tweak7, 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt16Avx512(in Span<byte> tweak, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		const int blockSize = 16 * 16;
		using CryptoBuffer<byte> buffer = new(blockSize);
		Span<byte> tweakBuffer = buffer.Span;

		GetInitTweak16Avx512(tweak, tweakBuffer);

		while (length >= 16 * BlockSize)
		{
			ReadOnlySpan<byte> src = source.Slice(offset, blockSize);
			Span<byte> dst = destination.Slice(offset, blockSize);

			FastUtils.Xor(src, tweakBuffer, dst, blockSize);

			if (_dataCrypto.HardwareAcceleration.HasFlag(BlockCryptoHardwareAcceleration.Block16))
			{
				_dataCrypto.Encrypt16(dst, dst);
			}
			else
			{
				_dataCrypto.Encrypt8(dst, dst);
				_dataCrypto.Encrypt8(dst.Slice(8 * 16), dst.Slice(8 * 16));
			}

			FastUtils.Xor(dst, tweakBuffer, blockSize);

			Gf128Mul16Avx512(tweakBuffer);

			offset += blockSize;
			length -= blockSize;
		}

		tweakBuffer.Slice(0, BlockSize).CopyTo(tweak);

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt32Avx512(in Span<byte> tweak, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		const int blockSize = 32 * 16;
		using CryptoBuffer<byte> buffer = new(blockSize);
		Span<byte> tweakBuffer = buffer.Span;

		GetInitTweak32Avx512(tweak, tweakBuffer);

		while (length >= 32 * BlockSize)
		{
			ReadOnlySpan<byte> src = source.Slice(offset, blockSize);
			Span<byte> dst = destination.Slice(offset, blockSize);

			FastUtils.Xor(src, tweakBuffer, dst, blockSize);

			if (_dataCrypto.HardwareAcceleration.HasFlag(BlockCryptoHardwareAcceleration.Block16))
			{
				_dataCrypto.Encrypt16(dst, dst);
				_dataCrypto.Encrypt16(dst.Slice(16 * 16), dst.Slice(16 * 16));
			}
			else
			{
				_dataCrypto.Encrypt8(dst.Slice(0 * 8 * 16), dst.Slice(0 * 8 * 16));
				_dataCrypto.Encrypt8(dst.Slice(1 * 8 * 16), dst.Slice(1 * 8 * 16));
				_dataCrypto.Encrypt8(dst.Slice(2 * 8 * 16), dst.Slice(2 * 8 * 16));
				_dataCrypto.Encrypt8(dst.Slice(3 * 8 * 16), dst.Slice(3 * 8 * 16));
			}

			FastUtils.Xor(dst, tweakBuffer, blockSize);

			Gf128Mul32Avx512(tweakBuffer);

			offset += blockSize;
			length -= blockSize;
		}

		tweakBuffer.Slice(0, BlockSize).CopyTo(tweak);

		return offset;
	}
}
