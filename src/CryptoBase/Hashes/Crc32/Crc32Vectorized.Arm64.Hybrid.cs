using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using Crc32Arm = System.Runtime.Intrinsics.Arm.Crc32;

namespace CryptoBase.Hashes.Crc32;

internal static partial class Crc32Vectorized
{
	private const int Arm64HybridNarrowScalarStripeSizeInBytes = 16;
	private const int Arm64HybridWideScalarStripeSizeInBytes = 24;
	private const int Arm64HybridVectorStripeSizeInBytes = 9 * 16;
	private const int Arm64HybridWideThresholdInBytes = 32 * 1024;

	internal static uint UpdateHybridArm64(uint state, ReadOnlySpan<byte> source, out int bytesConsumed)
	{
		return source.Length >= Arm64HybridWideThresholdInBytes
			? UpdateHybridArm64<WideArm64Hybrid>(state, source, out bytesConsumed)
			: UpdateHybridArm64<NarrowArm64Hybrid>(state, source, out bytesConsumed);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static uint UpdateHybridArm64<TMode>(uint state, ReadOnlySpan<byte> source, out int bytesConsumed)
	{
		Debug.Assert(Crc32Arm.Arm64.IsSupported && AesArm.IsSupported && AdvSimd.IsSupported);
		int scalarStripeSize = typeof(TMode) == typeof(WideArm64Hybrid) ? Arm64HybridWideScalarStripeSizeInBytes : Arm64HybridNarrowScalarStripeSizeInBytes;
		int blockSize = 3 * scalarStripeSize + Arm64HybridVectorStripeSizeInBytes;
		Debug.Assert(source.Length >= blockSize);

		int blockCount = source.Length / blockSize;
		int scalarLength = blockCount * scalarStripeSize;
		ref byte scalar0 = ref source.GetReference();
		ref byte scalar1 = ref Unsafe.Add(ref scalar0, scalarLength);
		ref byte scalar2 = ref Unsafe.Add(ref scalar1, scalarLength);
		ref byte vectors = ref Unsafe.Add(ref scalar2, scalarLength);
		uint crc1 = 0;
		uint crc2 = 0;

		Vector128<ulong> x0 = Load(ref vectors, 0);
		Vector128<ulong> x1 = Load(ref vectors, 16);
		Vector128<ulong> x2 = Load(ref vectors, 32);
		Vector128<ulong> x3 = Load(ref vectors, 48);
		Vector128<ulong> x4 = Load(ref vectors, 64);
		Vector128<ulong> x5 = Load(ref vectors, 80);
		Vector128<ulong> x6 = Load(ref vectors, 96);
		Vector128<ulong> x7 = Load(ref vectors, 112);
		Vector128<ulong> x8 = Load(ref vectors, 128);
		vectors = ref Unsafe.Add(ref vectors, Arm64HybridVectorStripeSizeInBytes);

		Vector128<ulong> fold1152 = Vector128.Create(0x26b70c3dUL, 0x3f41287aUL);
		Vector64<ulong> fold1152Lower = Vector64.Create(0x26b70c3dUL);

		for (int i = 1; i < blockCount; ++i)
		{
			Vector128<ulong> l0 = AesArm.PolynomialMultiplyWideningLower(x0.GetLower(), fold1152Lower);
			Vector128<ulong> l1 = AesArm.PolynomialMultiplyWideningLower(x1.GetLower(), fold1152Lower);
			Vector128<ulong> l2 = AesArm.PolynomialMultiplyWideningLower(x2.GetLower(), fold1152Lower);
			Vector128<ulong> l3 = AesArm.PolynomialMultiplyWideningLower(x3.GetLower(), fold1152Lower);
			Vector128<ulong> l4 = AesArm.PolynomialMultiplyWideningLower(x4.GetLower(), fold1152Lower);
			Vector128<ulong> l5 = AesArm.PolynomialMultiplyWideningLower(x5.GetLower(), fold1152Lower);
			Vector128<ulong> d0 = Load(ref vectors, 0);
			Vector128<ulong> d1 = Load(ref vectors, 16);
			Vector128<ulong> d2 = Load(ref vectors, 32);
			Vector128<ulong> d3 = Load(ref vectors, 48);
			Vector128<ulong> d4 = Load(ref vectors, 64);
			Vector128<ulong> d5 = Load(ref vectors, 80);
			Vector128<ulong> d6 = Load(ref vectors, 96);
			Vector128<ulong> d7 = Load(ref vectors, 112);
			Vector128<ulong> d8 = Load(ref vectors, 128);
			x0 = AesArm.PolynomialMultiplyWideningUpper(x0, fold1152) ^ l0 ^ d0;
			x1 = AesArm.PolynomialMultiplyWideningUpper(x1, fold1152) ^ l1 ^ d1;
			x2 = AesArm.PolynomialMultiplyWideningUpper(x2, fold1152) ^ l2 ^ d2;
			x3 = AesArm.PolynomialMultiplyWideningUpper(x3, fold1152) ^ l3 ^ d3;
			x4 = AesArm.PolynomialMultiplyWideningUpper(x4, fold1152) ^ l4 ^ d4;
			x5 = AesArm.PolynomialMultiplyWideningUpper(x5, fold1152) ^ l5 ^ d5;
			Vector128<ulong> l6 = AesArm.PolynomialMultiplyWideningLower(x6.GetLower(), fold1152Lower);
			x6 = AesArm.PolynomialMultiplyWideningUpper(x6, fold1152) ^ l6 ^ d6;
			Vector128<ulong> l7 = AesArm.PolynomialMultiplyWideningLower(x7.GetLower(), fold1152Lower);
			x7 = AesArm.PolynomialMultiplyWideningUpper(x7, fold1152) ^ l7 ^ d7;
			Vector128<ulong> l8 = AesArm.PolynomialMultiplyWideningLower(x8.GetLower(), fold1152Lower);
			x8 = AesArm.PolynomialMultiplyWideningUpper(x8, fold1152) ^ l8 ^ d8;

			UpdateScalarStripes<TMode>(ref state, ref crc1, ref crc2, ref scalar0, ref scalar1, ref scalar2);

			scalar0 = ref Unsafe.Add(ref scalar0, scalarStripeSize);
			scalar1 = ref Unsafe.Add(ref scalar1, scalarStripeSize);
			scalar2 = ref Unsafe.Add(ref scalar2, scalarStripeSize);
			vectors = ref Unsafe.Add(ref vectors, Arm64HybridVectorStripeSizeInBytes);
		}

		Vector128<ulong> foldPair = Vector128.Create(0xae689191UL, 0xccaa009eUL);
		Vector64<ulong> foldPairLower = foldPair.GetLower();
		x0 = FoldArm(x1, x0, foldPair, foldPairLower);
		x1 = x2;
		x2 = x3;
		x3 = x4;
		x4 = x5;
		x5 = x6;
		x6 = x7;
		x7 = x8;
		x0 = FoldArm(x1, x0, foldPair, foldPairLower);
		x2 = FoldArm(x3, x2, foldPair, foldPairLower);
		x4 = FoldArm(x5, x4, foldPair, foldPairLower);
		x6 = FoldArm(x7, x6, foldPair, foldPairLower);
		Vector128<ulong> foldPairs = Vector128.Create(0xf1da05aaUL, 0x81256527UL);
		Vector64<ulong> foldPairsLower = foldPairs.GetLower();
		x0 = FoldArm(x2, x0, foldPairs, foldPairsLower);
		x4 = FoldArm(x6, x4, foldPairs, foldPairsLower);
		Vector128<ulong> foldGroups = Vector128.Create(0x8f352d95UL, 0x1d9513d7UL);
		x0 = FoldArm(x4, x0, foldGroups, foldGroups.GetLower());

		UpdateScalarStripes<TMode>(ref state, ref crc1, ref crc2, ref scalar0, ref scalar1, ref scalar2);

		Vector128<ulong> shifted0 = ShiftCrcArm64(state, scalarLength * 2 + blockCount * Arm64HybridVectorStripeSizeInBytes);
		Vector128<ulong> shifted1 = ShiftCrcArm64(crc1, scalarLength + blockCount * Arm64HybridVectorStripeSizeInBytes);
		Vector128<ulong> shifted2 = ShiftCrcArm64(crc2, blockCount * Arm64HybridVectorStripeSizeInBytes);
		ulong combined = (shifted0 ^ shifted1 ^ shifted2).GetElement(0);
		state = Crc32Arm.Arm64.ComputeCrc32(0, x0.GetElement(0));
		state = Crc32Arm.Arm64.ComputeCrc32(state, combined ^ x0.GetElement(1));

		bytesConsumed = blockCount * blockSize;
		return state;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void UpdateScalarStripes<TMode>(ref uint crc0, ref uint crc1, ref uint crc2, ref byte stripe0, ref byte stripe1, ref byte stripe2)
	{
		if (typeof(TMode) == typeof(WideArm64Hybrid))
		{
			UpdateWideScalarStripes(ref crc0, ref crc1, ref crc2, ref stripe0, ref stripe1, ref stripe2);
		}
		else
		{
			UpdateNarrowScalarStripes(ref crc0, ref crc1, ref crc2, ref stripe0, ref stripe1, ref stripe2);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void UpdateNarrowScalarStripes(ref uint crc0, ref uint crc1, ref uint crc2, ref byte stripe0, ref byte stripe1, ref byte stripe2)
	{
		ulong value00 = Unsafe.ReadUnaligned<ulong>(ref stripe0);
		ulong value01 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe0, 8));
		ulong value10 = Unsafe.ReadUnaligned<ulong>(ref stripe1);
		ulong value11 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe1, 8));
		ulong value20 = Unsafe.ReadUnaligned<ulong>(ref stripe2);
		ulong value21 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe2, 8));
		crc0 = Crc32Arm.Arm64.ComputeCrc32(crc0, value00);
		crc1 = Crc32Arm.Arm64.ComputeCrc32(crc1, value10);
		crc2 = Crc32Arm.Arm64.ComputeCrc32(crc2, value20);
		crc0 = Crc32Arm.Arm64.ComputeCrc32(crc0, value01);
		crc1 = Crc32Arm.Arm64.ComputeCrc32(crc1, value11);
		crc2 = Crc32Arm.Arm64.ComputeCrc32(crc2, value21);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void UpdateWideScalarStripes(ref uint crc0, ref uint crc1, ref uint crc2, ref byte stripe0, ref byte stripe1, ref byte stripe2)
	{
		ulong value00 = Unsafe.ReadUnaligned<ulong>(ref stripe0);
		ulong value01 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe0, 8));
		ulong value02 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe0, 16));
		ulong value10 = Unsafe.ReadUnaligned<ulong>(ref stripe1);
		ulong value11 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe1, 8));
		ulong value12 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe1, 16));
		ulong value20 = Unsafe.ReadUnaligned<ulong>(ref stripe2);
		ulong value21 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe2, 8));
		ulong value22 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref stripe2, 16));
		crc0 = Crc32Arm.Arm64.ComputeCrc32(crc0, value00);
		crc1 = Crc32Arm.Arm64.ComputeCrc32(crc1, value10);
		crc2 = Crc32Arm.Arm64.ComputeCrc32(crc2, value20);
		crc0 = Crc32Arm.Arm64.ComputeCrc32(crc0, value01);
		crc1 = Crc32Arm.Arm64.ComputeCrc32(crc1, value11);
		crc2 = Crc32Arm.Arm64.ComputeCrc32(crc2, value21);
		crc0 = Crc32Arm.Arm64.ComputeCrc32(crc0, value02);
		crc1 = Crc32Arm.Arm64.ComputeCrc32(crc1, value12);
		crc2 = Crc32Arm.Arm64.ComputeCrc32(crc2, value22);
	}

	private static Vector128<ulong> ShiftCrcArm64(uint crc, int byteCount)
	{
		uint constant = XnModPArm64((ulong)byteCount * 8 - 33);
		return AesArm.PolynomialMultiplyWideningLower(Vector64.Create((ulong)crc), Vector64.Create((ulong)constant));
	}

	private static uint XnModPArm64(ulong power)
	{
		ulong stack = ~1UL;

		for (; power > 191; power = (power >> 1) - 16)
		{
			stack = (stack << 1) + (power & 1);
		}

		stack = ~stack;
		uint accumulator = 0x80000000U >> (int)(power & 31);

		for (power >>= 5; power > 0; --power)
		{
			accumulator = Crc32Arm.ComputeCrc32(accumulator, 0U);
		}

		while (true)
		{
			int shift = (int)(stack & 1);
			stack >>= 1;

			if (stack is 0)
			{
				break;
			}

			Vector64<byte> value = Vector64.CreateScalar(accumulator).AsByte();
			ulong square = AdvSimd.PolynomialMultiplyWideningLower(value, value).AsUInt64().GetElement(0);
			accumulator = Crc32Arm.Arm64.ComputeCrc32(0, square << shift);
		}

		return accumulator;
	}

	private readonly struct NarrowArm64Hybrid;

	private readonly struct WideArm64Hybrid;
}
