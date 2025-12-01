namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode128<TDataCipher, TTweakCipher>
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> Gf128MulV256(Vector256<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		Vector256<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector256<ulong> tmp2 = Pclmulqdq.V256.CarrylessMultiply(tmp1, Vector256.Create(0x87UL), 0x01);

		tmp1 = Avx2.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Encrypt8Avx2(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector256<byte> tweak01 = Vector256.Create(x0, x1);

		Vector256<byte> tweak23 = Gf128MulV256(tweak01, 2);
		Vector256<byte> tweak45 = Gf128MulV256(tweak01, 4);
		Vector256<byte> tweak67 = Gf128MulV256(tweak01, 6);

		while (length >= 8 * Block)
		{
			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			VectorBuffer128 dst = new VectorBuffer128
			{
				V256_0 = src.V256_0 ^ tweak01,
				V256_1 = src.V256_1 ^ tweak23,
				V256_2 = src.V256_2 ^ tweak45,
				V256_3 = src.V256_3 ^ tweak67
			};
			dst = _dataCipher.Encrypt(dst);
			VectorBuffer128 result = new VectorBuffer128
			{
				V256_0 = dst.V256_0 ^ tweak01,
				V256_1 = dst.V256_1 ^ tweak23,
				V256_2 = dst.V256_2 ^ tweak45,
				V256_3 = dst.V256_3 ^ tweak67
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128() = result;

			tweak01 = Gf128MulV256(tweak01, 8);
			tweak23 = Gf128MulV256(tweak23, 8);
			tweak45 = Gf128MulV256(tweak45, 8);
			tweak67 = Gf128MulV256(tweak67, 8);

			offset += 8 * Block;
			length -= 8 * Block;
		}

		tweak = tweak01.GetLower();

		return offset;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int Decrypt8Avx2(ref Vector128<byte> tweak, ReadOnlySpan<byte> source, Span<byte> destination, int length)
	{
		int offset = 0;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		Vector128<byte> x0 = tweak;
		Vector128<byte> x1 = Gf128MulV128(x0);
		Vector256<byte> tweak01 = Vector256.Create(x0, x1);

		Vector256<byte> tweak23 = Gf128MulV256(tweak01, 2);
		Vector256<byte> tweak45 = Gf128MulV256(tweak01, 4);
		Vector256<byte> tweak67 = Gf128MulV256(tweak01, 6);

		while (length >= 8 * Block)
		{
			VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), offset).AsVectorBuffer128();
			VectorBuffer128 dst = new VectorBuffer128
			{
				V256_0 = src.V256_0 ^ tweak01,
				V256_1 = src.V256_1 ^ tweak23,
				V256_2 = src.V256_2 ^ tweak45,
				V256_3 = src.V256_3 ^ tweak67
			};
			dst = _dataCipher.Decrypt(dst);
			VectorBuffer128 result = new VectorBuffer128
			{
				V256_0 = dst.V256_0 ^ tweak01,
				V256_1 = dst.V256_1 ^ tweak23,
				V256_2 = dst.V256_2 ^ tweak45,
				V256_3 = dst.V256_3 ^ tweak67
			};
			Unsafe.Add(ref destinationRef, offset).AsVectorBuffer128() = result;

			tweak01 = Gf128MulV256(tweak01, 8);
			tweak23 = Gf128MulV256(tweak23, 8);
			tweak45 = Gf128MulV256(tweak45, 8);
			tweak67 = Gf128MulV256(tweak67, 8);

			offset += 8 * Block;
			length -= 8 * Block;
		}

		tweak = tweak01.GetLower();

		return offset;
	}
}
