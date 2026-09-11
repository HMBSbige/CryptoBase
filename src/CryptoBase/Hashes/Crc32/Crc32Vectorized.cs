using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Hashes.Crc32;

internal static partial class Crc32Vectorized
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static uint UpdateArm<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		Debug.Assert(AesArm.IsSupported && AdvSimd.IsSupported);
		Debug.Assert(source.Length >= Vector128<byte>.Count);
		bool isIeee = Crc32Engine.IsIeee<TAlgorithm>();
		ulong k1 = isIeee ? 0x0000000154442bd4UL : 0x00000000740eef02UL;
		ulong k3 = isIeee ? 0x00000001751997d0UL : 0x00000000f20c0dfeUL;
		ulong k4 = isIeee ? 0x00000000ccaa009eUL : 0x000000014cd00bd6UL;
		Vector128<ulong> k1k2 = Vector128.Create(k1, isIeee ? 0x00000001c6e41596UL : 0x000000009e4addf8UL);
		Vector128<ulong> k3k4 = Vector128.Create(k3, k4);
		Vector64<ulong> k1Lower = Vector64.Create(k1);
		Vector64<ulong> k3Lower = Vector64.Create(k3);
		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;
		Vector128<ulong> x1;

		if (length >= Vector128<byte>.Count * 4)
		{
			x1 = Load(ref sourceRef, 0);
			Vector128<ulong> x2 = Load(ref sourceRef, 16);
			Vector128<ulong> x3 = Load(ref sourceRef, 32);
			Vector128<ulong> x4 = Load(ref sourceRef, 48);
			x1 ^= Vector128.CreateScalar(state).AsUInt64();
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count * 4);
			length -= Vector128<byte>.Count * 4;

			while (length >= Vector128<byte>.Count * 4)
			{
				Vector128<ulong> y5 = Load(ref sourceRef, 0);
				Vector128<ulong> y6 = Load(ref sourceRef, 16);
				Vector128<ulong> y7 = Load(ref sourceRef, 32);
				Vector128<ulong> y8 = Load(ref sourceRef, 48);
				Vector128<ulong> h1 = AesArm.PolynomialMultiplyWideningUpper(x1, k1k2);
				Vector128<ulong> h2 = AesArm.PolynomialMultiplyWideningUpper(x2, k1k2);
				Vector128<ulong> h3 = AesArm.PolynomialMultiplyWideningUpper(x3, k1k2);
				Vector128<ulong> h4 = AesArm.PolynomialMultiplyWideningUpper(x4, k1k2);
				Vector128<ulong> l1 = AesArm.PolynomialMultiplyWideningLower(x1.GetLower(), k1Lower);
				Vector128<ulong> l2 = AesArm.PolynomialMultiplyWideningLower(x2.GetLower(), k1Lower);
				Vector128<ulong> l3 = AesArm.PolynomialMultiplyWideningLower(x3.GetLower(), k1Lower);
				Vector128<ulong> l4 = AesArm.PolynomialMultiplyWideningLower(x4.GetLower(), k1Lower);
				x1 = y5 ^ h1 ^ l1;
				x2 = y6 ^ h2 ^ l2;
				x3 = y7 ^ h3 ^ l3;
				x4 = y8 ^ h4 ^ l4;
				sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count * 4);
				length -= Vector128<byte>.Count * 4;
			}

			x1 = FoldArm(x2, x1, k3k4, k3Lower);
			x1 = FoldArm(x3, x1, k3k4, k3Lower);
			x1 = FoldArm(x4, x1, k3k4, k3Lower);
		}
		else
		{
			x1 = Load(ref sourceRef, 0) ^ Vector128.CreateScalar(state).AsUInt64();
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		while (length >= Vector128<byte>.Count)
		{
			x1 = FoldArm(Load(ref sourceRef, 0), x1, k3k4, k3Lower);
			sourceRef = ref Unsafe.Add(ref sourceRef, Vector128<byte>.Count);
			length -= Vector128<byte>.Count;
		}

		Vector128<ulong> bitmask = Vector128.Create((ulong)uint.MaxValue);
		x1 = AdvSimd.ExtractVector128(x1.AsByte(), Vector128<byte>.Zero, 8).AsUInt64()
			^ AesArm.PolynomialMultiplyWideningLower(x1.GetLower(), Vector64.Create(k4));
		x1 = AesArm.PolynomialMultiplyWideningLower((x1 & bitmask).GetLower(), Vector64.Create(isIeee ? 0x0000000163cd6124UL : 0x00000000dd45aab8UL))
			^ AdvSimd.ExtractVector128(x1.AsByte(), Vector128<byte>.Zero, 4).AsUInt64();

		Vector128<ulong> reduction = AesArm.PolynomialMultiplyWideningLower((x1 & bitmask).GetLower(), Vector64.Create(isIeee ? 0x00000001f7011641UL : 0x00000000dea713f1UL)) & bitmask;
		reduction = AesArm.PolynomialMultiplyWideningLower(reduction.GetLower(), Vector64.Create(isIeee ? 0x00000001db710641UL : 0x0000000105ec76f1UL));
		x1 ^= reduction;
		return x1.AsUInt32().GetElement(1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Load(ref byte source, int offset)
	{
		return Vector128.LoadUnsafe(ref source, (nuint)offset).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> FoldArm(Vector128<ulong> target, Vector128<ulong> source, Vector128<ulong> constants, Vector64<ulong> lowerConstant)
	{
		return target ^ AesArm.PolynomialMultiplyWideningUpper(source, constants) ^ AesArm.PolynomialMultiplyWideningLower(source.GetLower(), lowerConstant);
	}
}
