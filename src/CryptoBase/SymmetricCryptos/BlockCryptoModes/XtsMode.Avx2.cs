namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Gf128Mul(in Vector256<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector256<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector256<ulong> tmp2 = Pclmulqdq.V256.CarrylessMultiply(tmp1, Vector256.Create(0x87UL), 0x01);

		tmp1 = Avx2.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetInitTweak8Avx2(in ReadOnlySpan<byte> tweakBuffer, in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref readonly Vector128<byte> x0 = ref Unsafe.As<byte, Vector128<byte>>(ref tweakBuffer.GetReference());
		ref Vector256<byte> tweak0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 0 * 32));
		ref Vector256<byte> tweak1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 1 * 32));
		ref Vector256<byte> tweak2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 2 * 32));
		ref Vector256<byte> tweak3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 3 * 32));

		Vector128<byte> x1 = Gf128Mul(x0);
		tweak0 = Vector256.Create(x0, x1);

		tweak1 = Gf128Mul(tweak0, 2);
		tweak2 = Gf128Mul(tweak0, 4);
		tweak3 = Gf128Mul(tweak0, 6);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul8Avx2(in Span<byte> buffer)
	{
		ref byte ptr = ref buffer.GetReference();
		ref Vector256<byte> tweak0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 0 * 32));
		ref Vector256<byte> tweak1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 1 * 32));
		ref Vector256<byte> tweak2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 2 * 32));
		ref Vector256<byte> tweak3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref ptr, 3 * 32));

		tweak0 = Gf128Mul(tweak0, 8);
		tweak1 = Gf128Mul(tweak1, 8);
		tweak2 = Gf128Mul(tweak2, 8);
		tweak3 = Gf128Mul(tweak3, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt8Avx2(in Span<byte> tweak, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		const int blockSize = 8 * 16;
		using CryptoBuffer<byte> buffer = new(blockSize);
		Span<byte> tweakBuffer = buffer.Span;

		GetInitTweak8Avx2(tweak, tweakBuffer);

		while (length >= 8 * BlockSize)
		{
			ReadOnlySpan<byte> src = source.Slice(offset, blockSize);
			Span<byte> dst = destination.Slice(offset, blockSize);

			FastUtils.Xor(src, tweakBuffer, dst, blockSize);
			_dataCrypto.Encrypt8(dst, dst);
			FastUtils.Xor(dst, tweakBuffer, blockSize);

			Gf128Mul8Avx2(tweakBuffer);

			offset += blockSize;
			length -= blockSize;
		}

		tweakBuffer.Slice(0, BlockSize).CopyTo(tweak);

		return offset;
	}
}
