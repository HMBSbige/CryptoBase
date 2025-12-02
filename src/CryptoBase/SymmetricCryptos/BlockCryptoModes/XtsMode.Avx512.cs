namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode<TBlockCipher>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Gf128MulAvx512(Vector512<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector512<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector512<ulong> tmp2 = Pclmulqdq.V512.CarrylessMultiply(tmp1, Vector512.Create(0x87UL), 0x01);

		tmp1 = Avx512BW.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static VectorBuffer256 GetInitTweak16Avx512(Vector128<byte> tweak)
	{
		Unsafe.SkipInit(out VectorBuffer256 r);
		r.V128_0 = tweak;
		r.V128_1 = Gf128MulSse2(tweak, 1);
		r.V128_2 = Gf128MulSse2(tweak, 2);
		r.V128_3 = Gf128MulSse2(tweak, 3);

		r.V512_1 = Gf128MulAvx512(r.V512_0, 4);
		r.V512_2 = Gf128MulAvx512(r.V512_0, 8);
		r.V512_3 = Gf128MulAvx512(r.V512_0, 12);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul16Avx512(ref VectorBuffer256 tweak)
	{
		tweak.V512_0 = Gf128MulAvx512(tweak.V512_0, 16);
		tweak.V512_1 = Gf128MulAvx512(tweak.V512_1, 16);
		tweak.V512_2 = Gf128MulAvx512(tweak.V512_2, 16);
		tweak.V512_3 = Gf128MulAvx512(tweak.V512_3, 16);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static VectorBuffer512 GetInitTweak32Avx512(Vector128<byte> tweak)
	{
		Unsafe.SkipInit(out VectorBuffer512 r);
		r.Lower.V128_0 = tweak;
		r.Lower.V128_1 = Gf128MulSse2(tweak, 1);
		r.Lower.V128_2 = Gf128MulSse2(tweak, 2);
		r.Lower.V128_3 = Gf128MulSse2(tweak, 3);

		r.V512_1 = Gf128MulAvx512(r.V512_0, 4);
		r.V512_2 = Gf128MulAvx512(r.V512_0, 8);
		r.V512_3 = Gf128MulAvx512(r.V512_0, 12);
		r.V512_4 = Gf128MulAvx512(r.V512_0, 16);
		r.V512_5 = Gf128MulAvx512(r.V512_0, 20);
		r.V512_6 = Gf128MulAvx512(r.V512_0, 24);
		r.V512_7 = Gf128MulAvx512(r.V512_0, 28);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Gf128Mul32Avx512(ref VectorBuffer512 tweak)
	{
		tweak.V512_0 = Gf128MulAvx512(tweak.V512_0, 32);
		tweak.V512_1 = Gf128MulAvx512(tweak.V512_1, 32);
		tweak.V512_2 = Gf128MulAvx512(tweak.V512_2, 32);
		tweak.V512_3 = Gf128MulAvx512(tweak.V512_3, 32);
		tweak.V512_4 = Gf128MulAvx512(tweak.V512_4, 32);
		tweak.V512_5 = Gf128MulAvx512(tweak.V512_5, 32);
		tweak.V512_6 = Gf128MulAvx512(tweak.V512_6, 32);
		tweak.V512_7 = Gf128MulAvx512(tweak.V512_7, 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt16Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer256 tweakBuffer = GetInitTweak16Avx512(tweak);

		while (length >= 16 * BlockBytesSize)
		{
			VectorBuffer256 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer256();
			ref VectorBuffer256 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer256();

			VectorBuffer256 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Encrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul16Avx512(ref tweakBuffer);

			offset += 16 * BlockBytesSize;
			length -= 16 * BlockBytesSize;
		}

		tweak = tweakBuffer.V128_0;

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt32Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer512 tweakBuffer = GetInitTweak32Avx512(tweak);

		while (length >= 32 * BlockBytesSize)
		{
			VectorBuffer512 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer512();
			ref VectorBuffer512 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer512();

			VectorBuffer512 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Encrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul32Avx512(ref tweakBuffer);

			offset += 32 * BlockBytesSize;
			length -= 32 * BlockBytesSize;
		}

		tweak = tweakBuffer.Lower.V128_0;

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt16Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer256 tweakBuffer = GetInitTweak16Avx512(tweak);

		while (length >= 16 * BlockBytesSize)
		{
			VectorBuffer256 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer256();
			ref VectorBuffer256 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer256();

			VectorBuffer256 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Decrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul16Avx512(ref tweakBuffer);

			offset += 16 * BlockBytesSize;
			length -= 16 * BlockBytesSize;
		}

		tweak = tweakBuffer.V128_0;

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt32Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int length = source.Length;
		int offset = 0;

		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		VectorBuffer512 tweakBuffer = GetInitTweak32Avx512(tweak);

		while (length >= 32 * BlockBytesSize)
		{
			VectorBuffer512 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer512();
			ref VectorBuffer512 dst = ref Unsafe.Add(ref destinationRef, offset).AsVectorBuffer512();

			VectorBuffer512 tmp = src ^ tweakBuffer;
			tmp = _dataCipher.Decrypt(tmp);
			dst = tmp ^ tweakBuffer;

			Gf128Mul32Avx512(ref tweakBuffer);

			offset += 32 * BlockBytesSize;
			length -= 32 * BlockBytesSize;
		}

		tweak = tweakBuffer.Lower.V128_0;

		return offset;
	}
}
