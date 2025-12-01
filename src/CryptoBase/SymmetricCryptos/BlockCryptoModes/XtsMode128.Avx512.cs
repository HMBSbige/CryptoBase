namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode128<TDataCipher, TTweakCipher>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> Gf128MulV512(Vector512<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector512<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector512<ulong> tmp2 = Pclmulqdq.V512.CarrylessMultiply(tmp1, Vector512.Create(0x87UL), 0x01);

		tmp1 = Avx512BW.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt16Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector128<byte> x2 = Gf128MulV128(x0, 2);
		Vector128<byte> x3 = Gf128MulV128(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		Vector512<byte> tweak0123 = t;

		Vector512<byte> tweak4567 = Gf128MulV512(tweak0123, 4);
		Vector512<byte> tweak89AB = Gf128MulV512(tweak0123, 8);
		Vector512<byte> tweakCDEF = Gf128MulV512(tweak0123, 12);

		while (length >= 16 * Block)
		{
			VectorBuffer256 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer256();
			VectorBuffer256 dst = new VectorBuffer256
			{
				V512_0 = src.V512_0 ^ tweak0123,
				V512_1 = src.V512_1 ^ tweak4567,
				V512_2 = src.V512_2 ^ tweak89AB,
				V512_3 = src.V512_3 ^ tweakCDEF
			};

			dst = _dataCipher.Encrypt(dst);

			VectorBuffer256 result = new VectorBuffer256
			{
				V512_0 = dst.V512_0 ^ tweak0123,
				V512_1 = dst.V512_1 ^ tweak4567,
				V512_2 = dst.V512_2 ^ tweak89AB,
				V512_3 = dst.V512_3 ^ tweakCDEF
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer256() = result;

			tweak0123 = Gf128MulV512(tweak0123, 16);
			tweak4567 = Gf128MulV512(tweak4567, 16);
			tweak89AB = Gf128MulV512(tweak89AB, 16);
			tweakCDEF = Gf128MulV512(tweakCDEF, 16);

			offset += 16 * Block;
			length -= 16 * Block;
		}

		tweak = tweak0123.GetLower().GetLower();

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt32Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector128<byte> x2 = Gf128MulV128(x0, 2);
		Vector128<byte> x3 = Gf128MulV128(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		Vector512<byte> tweak0123 = t;

		Vector512<byte> tweak4567 = Gf128MulV512(tweak0123, 4);
		Vector512<byte> tweak89AB = Gf128MulV512(tweak0123, 8);
		Vector512<byte> tweakCDEF = Gf128MulV512(tweak0123, 12);
		Vector512<byte> tweakGHIJ = Gf128MulV512(tweak0123, 16);
		Vector512<byte> tweakKLMN = Gf128MulV512(tweak0123, 20);
		Vector512<byte> tweakOPQR = Gf128MulV512(tweak0123, 24);
		Vector512<byte> tweakSTUV = Gf128MulV512(tweak0123, 28);

		while (length >= 32 * Block)
		{
			VectorBuffer512 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer512();
			VectorBuffer512 dst = new VectorBuffer512
			{
				V512_0 = src.V512_0 ^ tweak0123,
				V512_1 = src.V512_1 ^ tweak4567,
				V512_2 = src.V512_2 ^ tweak89AB,
				V512_3 = src.V512_3 ^ tweakCDEF,
				V512_4 = src.V512_4 ^ tweakGHIJ,
				V512_5 = src.V512_5 ^ tweakKLMN,
				V512_6 = src.V512_6 ^ tweakOPQR,
				V512_7 = src.V512_7 ^ tweakSTUV
			};

			dst = _dataCipher.Encrypt(dst);

			VectorBuffer512 result = new VectorBuffer512
			{
				V512_0 = dst.V512_0 ^ tweak0123,
				V512_1 = dst.V512_1 ^ tweak4567,
				V512_2 = dst.V512_2 ^ tweak89AB,
				V512_3 = dst.V512_3 ^ tweakCDEF,
				V512_4 = dst.V512_4 ^ tweakGHIJ,
				V512_5 = dst.V512_5 ^ tweakKLMN,
				V512_6 = dst.V512_6 ^ tweakOPQR,
				V512_7 = dst.V512_7 ^ tweakSTUV
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer512() = result;

			tweak0123 = Gf128MulV512(tweak0123, 32);
			tweak4567 = Gf128MulV512(tweak4567, 32);
			tweak89AB = Gf128MulV512(tweak89AB, 32);
			tweakCDEF = Gf128MulV512(tweakCDEF, 32);
			tweakGHIJ = Gf128MulV512(tweakGHIJ, 32);
			tweakKLMN = Gf128MulV512(tweakKLMN, 32);
			tweakOPQR = Gf128MulV512(tweakOPQR, 32);
			tweakSTUV = Gf128MulV512(tweakSTUV, 32);

			offset += 32 * Block;
			length -= 32 * Block;
		}

		tweak = tweak0123.GetLower().GetLower();

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt16Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector128<byte> x2 = Gf128MulV128(x0, 2);
		Vector128<byte> x3 = Gf128MulV128(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		Vector512<byte> tweak0123 = t;

		Vector512<byte> tweak4567 = Gf128MulV512(tweak0123, 4);
		Vector512<byte> tweak89AB = Gf128MulV512(tweak0123, 8);
		Vector512<byte> tweakCDEF = Gf128MulV512(tweak0123, 12);

		while (length >= 16 * Block)
		{
			VectorBuffer256 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer256();
			VectorBuffer256 dst = new VectorBuffer256
			{
				V512_0 = src.V512_0 ^ tweak0123,
				V512_1 = src.V512_1 ^ tweak4567,
				V512_2 = src.V512_2 ^ tweak89AB,
				V512_3 = src.V512_3 ^ tweakCDEF
			};

			dst = _dataCipher.Decrypt(dst);

			VectorBuffer256 result = new VectorBuffer256
			{
				V512_0 = dst.V512_0 ^ tweak0123,
				V512_1 = dst.V512_1 ^ tweak4567,
				V512_2 = dst.V512_2 ^ tweak89AB,
				V512_3 = dst.V512_3 ^ tweakCDEF
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer256() = result;

			tweak0123 = Gf128MulV512(tweak0123, 16);
			tweak4567 = Gf128MulV512(tweak4567, 16);
			tweak89AB = Gf128MulV512(tweak89AB, 16);
			tweakCDEF = Gf128MulV512(tweakCDEF, 16);

			offset += 16 * Block;
			length -= 16 * Block;
		}

		tweak = tweak0123.GetLower().GetLower();

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt32Avx512(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector128<byte> x2 = Gf128MulV128(x0, 2);
		Vector128<byte> x3 = Gf128MulV128(x0, 3);
		Vector512<byte> t = default;
		t = Avx512F.InsertVector128(t, x0, 0);
		t = Avx512F.InsertVector128(t, x1, 1);
		t = Avx512F.InsertVector128(t, x2, 2);
		t = Avx512F.InsertVector128(t, x3, 3);
		Vector512<byte> tweak0123 = t;

		Vector512<byte> tweak4567 = Gf128MulV512(tweak0123, 4);
		Vector512<byte> tweak89AB = Gf128MulV512(tweak0123, 8);
		Vector512<byte> tweakCDEF = Gf128MulV512(tweak0123, 12);
		Vector512<byte> tweakGHIJ = Gf128MulV512(tweak0123, 16);
		Vector512<byte> tweakKLMN = Gf128MulV512(tweak0123, 20);
		Vector512<byte> tweakOPQR = Gf128MulV512(tweak0123, 24);
		Vector512<byte> tweakSTUV = Gf128MulV512(tweak0123, 28);

		while (length >= 32 * Block)
		{
			VectorBuffer512 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer512();
			VectorBuffer512 dst = new VectorBuffer512
			{
				V512_0 = src.V512_0 ^ tweak0123,
				V512_1 = src.V512_1 ^ tweak4567,
				V512_2 = src.V512_2 ^ tweak89AB,
				V512_3 = src.V512_3 ^ tweakCDEF,
				V512_4 = src.V512_4 ^ tweakGHIJ,
				V512_5 = src.V512_5 ^ tweakKLMN,
				V512_6 = src.V512_6 ^ tweakOPQR,
				V512_7 = src.V512_7 ^ tweakSTUV
			};

			dst = _dataCipher.Decrypt(dst);

			VectorBuffer512 result = new VectorBuffer512
			{
				V512_0 = dst.V512_0 ^ tweak0123,
				V512_1 = dst.V512_1 ^ tweak4567,
				V512_2 = dst.V512_2 ^ tweak89AB,
				V512_3 = dst.V512_3 ^ tweakCDEF,
				V512_4 = dst.V512_4 ^ tweakGHIJ,
				V512_5 = dst.V512_5 ^ tweakKLMN,
				V512_6 = dst.V512_6 ^ tweakOPQR,
				V512_7 = dst.V512_7 ^ tweakSTUV
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer512() = result;

			tweak0123 = Gf128MulV512(tweak0123, 32);
			tweak4567 = Gf128MulV512(tweak4567, 32);
			tweak89AB = Gf128MulV512(tweak89AB, 32);
			tweakCDEF = Gf128MulV512(tweakCDEF, 32);
			tweakGHIJ = Gf128MulV512(tweakGHIJ, 32);
			tweakKLMN = Gf128MulV512(tweakKLMN, 32);
			tweakOPQR = Gf128MulV512(tweakOPQR, 32);
			tweakSTUV = Gf128MulV512(tweakSTUV, 32);

			offset += 32 * Block;
			length -= 32 * Block;
		}

		tweak = tweak0123.GetLower().GetLower();

		return offset;
	}
}
