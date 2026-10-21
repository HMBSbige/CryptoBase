namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashArmPrecomputedKey
{
	internal Vector128<byte> Key1;
	internal Vector128<byte> Key2;
	internal Vector128<byte> Key3;
	internal Vector128<byte> Key4;
	internal Vector128<byte> Key5;
	internal Vector128<byte> Key6;
	internal Vector128<byte> Key7;
	internal Vector128<byte> Key8;

	// internalKey must already have the bits in each byte reversed.
	internal void Initialize(Vector128<byte> internalKey)
	{
		Key1 = internalKey;
		Key2 = GHashArm.GFSquare(Key1);
		Key3 = GHashArm.GFMultiply(Key2, Key1);
		Key4 = GHashArm.GFSquare(Key2);
		Key5 = GHashArm.GFMultiply(Key4, Key1);
		Key6 = GHashArm.GFSquare(Key3);
		Key7 = GHashArm.GFMultiply(Key4, Key3);
		Key8 = GHashArm.GFSquare(Key4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source)
	{
		int remainingBlocks = (int)(GHash.GetPaddedLength(source.Length) / GHash.BlockSizeInBytes);
		Debug.Assert(remainingBlocks is > 0 and <= 8);
		ReadOnlySpan<Vector128<byte>> powers = MemoryMarshal.CreateReadOnlySpan(in Key1, 8).Slice(0, remainingBlocks);
		Vector128<byte> initial = AdvSimd.Arm64.ReverseElementBits(accumulator);
		Vector128<ulong> low = default;
		Vector128<ulong> high = default;
		Vector128<ulong> middle = default;
		AccumulateSegment(source, powers, ref remainingBlocks, ref initial, ref low, ref high, ref middle);
		accumulator = AdvSimd.Arm64.ReverseElementBits(GHashArm.ReduceSchoolbookProduct(low, high, middle ^ low ^ high));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateSegment(scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<Vector128<byte>> powers, ref int remainingBlocks, ref Vector128<byte> initial, ref Vector128<ulong> low, ref Vector128<ulong> high, ref Vector128<ulong> middle)
	{
		int completeLength = source.Length & -GHash.BlockSizeInBytes;
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref Vector128<byte> power = ref MemoryMarshal.GetReference(powers);

		for (int offset = 0; offset < completeLength; offset += GHash.BlockSizeInBytes)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref input, (nuint)offset)) ^ initial;
			GHashArm.AccumulateProduct(block, Unsafe.Add(ref power, --remainingBlocks), ref low, ref high, ref middle);
			initial = default;
		}

		if (completeLength < source.Length)
		{
			Vector128<byte> finalBlock = Vector128.LoadPartialUnsafe(ref input, (nuint)completeLength, source.Length - completeLength);
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(finalBlock) ^ initial;
			GHashArm.AccumulateProduct(block, Unsafe.Add(ref power, --remainingBlocks), ref low, ref high, ref middle);
			initial = default;
		}
	}
}
