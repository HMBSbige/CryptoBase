namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode<TBlockCipher>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Gf128MulAvx2(Vector256<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector256<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector256<ulong> tmp2 = Pclmulqdq.V256.CarrylessMultiply(tmp1, Vector256.Create(0x87UL), 0x01);

		tmp1 = Avx2.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static VectorBuffer128 GetInitTweak8Avx2(Vector128<byte> tweak)
	{
		Unsafe.SkipInit(out VectorBuffer128 r);
		r.V128_0 = tweak;
		r.V128_1 = Gf128MulSse2(tweak, 1);

		r.V256_1 = Gf128MulAvx2(r.V256_0, 2);
		r.V256_2 = Gf128MulAvx2(r.V256_0, 4);
		r.V256_3 = Gf128MulAvx2(r.V256_0, 6);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul8Avx2(ref VectorBuffer128 tweak)
	{
		tweak.V256_0 = Gf128MulAvx2(tweak.V256_0, 8);
		tweak.V256_1 = Gf128MulAvx2(tweak.V256_1, 8);
		tweak.V256_2 = Gf128MulAvx2(tweak.V256_2, 8);
		tweak.V256_3 = Gf128MulAvx2(tweak.V256_3, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt8Avx2(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer128 tweakBuffer = GetInitTweak8Avx2(tweak);

		while (length >= 8 * BlockBytesSize)
		{
			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128();

			VectorBuffer128 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Encrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul8Avx2(ref tweakBuffer);

			offset += 8 * BlockBytesSize;
			length -= 8 * BlockBytesSize;
		}

		tweak = tweakBuffer.V128_0;

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt8Avx2(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer128 tweakBuffer = GetInitTweak8Avx2(tweak);

		while (length >= 8 * BlockBytesSize)
		{
			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128();

			VectorBuffer128 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Decrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul8Avx2(ref tweakBuffer);

			offset += 8 * BlockBytesSize;
			length -= 8 * BlockBytesSize;
		}

		tweak = tweakBuffer.V128_0;

		return offset;
	}
}
