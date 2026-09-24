namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class GHashNeon
{
	internal static bool IsSupported => AdvSimd.Arm64.IsSupported;

	internal static void AppendPaddedSegments(ref Vector128<byte> accumulator, in Vector128<byte> key, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second, scoped ReadOnlySpan<byte> third)
	{
		Debug.Assert(IsSupported);
		Vector128<byte> internalKey = AdvSimd.Arm64.ReverseElementBits(key);
		Vector128<byte> internalAccumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
		Vector128<byte> finalBlock = default;

		try
		{
			AppendPaddedSegment(ref internalAccumulator, internalKey, first, ref finalBlock);
			AppendPaddedSegment(ref internalAccumulator, internalKey, second, ref finalBlock);
			AppendPaddedSegment(ref internalAccumulator, internalKey, third, ref finalBlock);
			accumulator = AdvSimd.Arm64.ReverseElementBits(internalAccumulator);
		}
		finally
		{
			internalKey.ZeroMemory();
			internalAccumulator.ZeroMemory();
			finalBlock.ZeroMemory();
		}
	}

	private static void AppendPaddedSegment(ref Vector128<byte> accumulator, Vector128<byte> key, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -GHash.BlockSizeInBytes;
		AppendBlocks(ref accumulator, key, source.Slice(0, completeLength));
		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			return;
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		AppendBlocks(ref accumulator, key, finalBlock.AsReadOnlySpan());
	}

	private static void AppendBlocks(ref Vector128<byte> accumulator, Vector128<byte> key, scoped ReadOnlySpan<byte> source)
	{
		ref byte input = ref source.GetReference();
		Vector128<byte> value = accumulator;

		for (int remaining = source.Length; remaining > 0; remaining -= GHash.BlockSizeInBytes)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref input));
			value = Multiply(block ^ value, key);
			input = ref Unsafe.Add(ref input, GHash.BlockSizeInBytes);
		}

		accumulator = value;
	}

	private static Vector128<byte> Multiply(Vector128<byte> value, Vector128<byte> key)
	{
		Vector64<byte> valueLow = value.GetLower();
		Vector64<byte> valueHigh = value.GetUpper();
		Vector64<byte> keyLow = key.GetLower();
		Vector64<byte> keyHigh = key.GetUpper();
		Vector128<ulong> low = CarrylessMultiply64(valueLow, keyLow);
		Vector128<ulong> high = CarrylessMultiply64(valueHigh, keyHigh);
		Vector128<ulong> middle = CarrylessMultiply64(valueLow ^ valueHigh, keyLow ^ keyHigh) ^ low ^ high;
		low ^= AdvSimd.ExtractVector128(Vector128<ulong>.Zero, middle, 1);
		high ^= AdvSimd.ExtractVector128(middle, Vector128<ulong>.Zero, 1);

		Vector128<ulong> overflow = high >> 63 ^ high >> 62 ^ high >> 57;
		Vector128<ulong> folded = high ^ high << 1 ^ high << 2 ^ high << 7;
		Vector128<ulong> excess = AdvSimd.ExtractVector128(overflow, Vector128<ulong>.Zero, 1);
		return (low ^ folded ^ AdvSimd.ExtractVector128(Vector128<ulong>.Zero, overflow, 1) ^ excess ^ excess << 1 ^ excess << 2 ^ excess << 7).AsByte();
	}
}
