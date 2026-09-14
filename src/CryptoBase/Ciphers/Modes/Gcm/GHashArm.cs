using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static class GHashArm
{
	internal const int BlockSize = GHash.BlockSizeInBytes;
	private const int FoldedBlockSize = 4 * BlockSize;
	private const int FoldedThreshold = 8 * BlockSize;

	internal static bool IsSupported => AesArm.IsSupported;

	[SkipLocalsInit]
	internal static void AppendPaddedSegments(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Debug.Assert(IsSupported);
		long firstPaddedLength = GHash.GetPaddedLength(first.Length);
		long secondPaddedLength = GHash.GetPaddedLength(second.Length);
		long thirdPaddedLength = GHash.GetPaddedLength(third.Length);
		long totalPaddedLength = firstPaddedLength + secondPaddedLength + thirdPaddedLength;
		long maximumPaddedLength = Math.Max(firstPaddedLength, Math.Max(secondPaddedLength, thirdPaddedLength));

		if (totalPaddedLength >= FoldedThreshold && maximumPaddedLength >= FoldedBlockSize)
		{
			AppendPaddedSegmentsFolded(ref accumulator, in key, first, second, third);
			return;
		}

		Vector128<byte> internalKey = AdvSimd.Arm64.ReverseElementBits(key);
		Vector128<byte> internalAccumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
		Unsafe.SkipInit(out Vector128<byte> finalBlock);

		try
		{
			AppendPaddedSegment(ref internalAccumulator, in internalKey, first, ref finalBlock);
			AppendPaddedSegment(ref internalAccumulator, in internalKey, second, ref finalBlock);
			AppendPaddedSegment(ref internalAccumulator, in internalKey, third, ref finalBlock);
			accumulator = AdvSimd.Arm64.ReverseElementBits(internalAccumulator);
		}
		finally
		{
			finalBlock.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendSequential(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source)
	{
		while (!source.IsEmpty)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source.GetReference()));
			accumulator = GFMultiply(block ^ accumulator, key);
			source = source.Slice(BlockSize);
		}
	}

	private static void AppendPaddedSegment(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -BlockSize;

		if (completeLength is not 0)
		{
			AppendSequential(ref accumulator, in key, source.Slice(0, completeLength));
		}

		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			return;
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		ReadOnlySpan<byte> block = finalBlock.AsReadOnlySpan();
		AppendSequential(ref accumulator, in key, block);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[SkipLocalsInit]
	private static void AppendPaddedSegmentsFolded(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Vector128<byte> internalKey = AdvSimd.Arm64.ReverseElementBits(key);
		GHashArmFoldedState state = new(internalKey, AdvSimd.Arm64.ReverseElementBits(accumulator));
		Unsafe.SkipInit(out Vector128<byte> finalBlock);

		try
		{
			state.AppendPaddedSegment(first, ref finalBlock);
			state.AppendPaddedSegment(second, ref finalBlock);
			state.AppendPaddedSegment(third, ref finalBlock);
			accumulator = AdvSimd.Arm64.ReverseElementBits(state.GetAccumulator());
		}
		finally
		{
			state.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GFMultiply(Vector128<byte> a, in Vector128<byte> b)
	{
		GFMultiplyUnreduced(a, b, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		AssembleProduct(lowProduct, highProduct, middleProduct, out Vector128<uint> low, out Vector128<uint> high);
		return Reduce(low, high);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> GFSquare(Vector128<byte> value)
	{
		Vector128<ulong> limbs = value.AsUInt64();
		Vector128<ulong> low = AesArm.PolynomialMultiplyWideningLower(limbs.GetLower(), limbs.GetLower());
		Vector128<ulong> high = AesArm.PolynomialMultiplyWideningUpper(limbs, limbs);
		return Reduce(low.AsUInt32(), high.AsUInt32());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void GFMultiplyUnreduced(Vector128<byte> a, Vector128<byte> b, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle)
	{
		Vector128<ulong> a64 = a.AsUInt64();
		Vector128<ulong> b64 = b.AsUInt64();
		Vector64<ulong> aLow = a64.GetLower();
		Vector64<ulong> bLow = b64.GetLower();
		Vector64<ulong> aSum = aLow ^ a64.GetUpper();
		Vector64<ulong> bSum = bLow ^ b64.GetUpper();

		low = AesArm.PolynomialMultiplyWideningLower(aLow, bLow);
		high = AesArm.PolynomialMultiplyWideningUpper(a64, b64);
		middle = AesArm.PolynomialMultiplyWideningLower(aSum, bSum);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AssembleProduct(Vector128<ulong> lowProduct, Vector128<ulong> highProduct, Vector128<ulong> middleProduct, out Vector128<uint> low, out Vector128<uint> high)
	{
		middleProduct ^= lowProduct ^ highProduct;
		low = (lowProduct ^ AdvSimd.ExtractVector128(Vector128<ulong>.Zero, middleProduct, 1)).AsUInt32();
		high = (highProduct ^ AdvSimd.ExtractVector128(middleProduct, Vector128<ulong>.Zero, 1)).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AccumulateProduct(Vector128<byte> value, Vector128<byte> key, ref Vector128<ulong> lowProduct, ref Vector128<ulong> highProduct, ref Vector128<ulong> middleProduct)
	{
		GFMultiplyUnreduced(value, key, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle);
		lowProduct ^= low;
		highProduct ^= high;
		middleProduct ^= middle;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Reduce(Vector128<uint> low, Vector128<uint> high)
	{
		Vector128<ulong> polynomial = Vector128.Create(0x87UL);
		Vector128<ulong> high64 = high.AsUInt64();
		Vector128<ulong> firstFold = AesArm.PolynomialMultiplyWideningUpper(high64, polynomial);
		high64 ^= AdvSimd.ExtractVector128(firstFold, Vector128<ulong>.Zero, 1);
		Vector128<ulong> low64 = low.AsUInt64() ^ AdvSimd.ExtractVector128(Vector128<ulong>.Zero, firstFold, 1);
		return (low64 ^ AesArm.PolynomialMultiplyWideningLower(high64.GetLower(), polynomial.GetLower())).AsByte();
	}
}
