namespace CryptoBase.Ciphers.Modes.Gcm;

internal readonly struct GHashArmPrecomputedKey
{
	internal readonly Vector128<byte> Key1;
	internal readonly Vector128<byte> Key2;
	internal readonly Vector128<byte> Key3;
	internal readonly Vector128<byte> Key4;
	internal readonly Vector128<byte> Key5;
	internal readonly Vector128<byte> Key6;
	internal readonly Vector128<byte> Key7;
	internal readonly Vector128<byte> Key8;

	// internalKey must already have the bits in each byte reversed.
	internal GHashArmPrecomputedKey(Vector128<byte> internalKey)
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
	internal void AppendPaddedSegments(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> first, scoped ReadOnlySpan<byte> second)
	{
		if (first.IsEmpty)
		{
			first = second;
			second = default;
		}

		if (first.Length is GHash.BlockSizeInBytes && second.IsEmpty)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref first.GetReference()) ^ accumulator);
			GHashArm.GFMultiplyUnreduced(block, Key1, out Vector128<ulong> singleLow, out Vector128<ulong> singleHigh, out Vector128<ulong> singleMiddle);
			accumulator = AdvSimd.Arm64.ReverseElementBits(GHashArm.ReduceSchoolbookProduct(singleLow, singleHigh, singleMiddle ^ singleLow ^ singleHigh));
			return;
		}

		int remainingBlocks = (int)((GHash.GetPaddedLength(first.Length) + GHash.GetPaddedLength(second.Length)) / GHash.BlockSizeInBytes);
		Debug.Assert(remainingBlocks is > 0 and <= 8);
		ReadOnlySpan<Vector128<byte>> powers = MemoryMarshal.CreateReadOnlySpan(in Key1, 8).Slice(0, remainingBlocks);
		Vector128<byte> initial = AdvSimd.Arm64.ReverseElementBits(accumulator);
		Vector128<ulong> low = default;
		Vector128<ulong> high = default;
		Vector128<ulong> middle = default;
		AccumulateSegment(first, powers, ref remainingBlocks, ref initial, ref low, ref high, ref middle);
		AccumulateSegment(second, powers, ref remainingBlocks, ref initial, ref low, ref high, ref middle);
		accumulator = AdvSimd.Arm64.ReverseElementBits(GHashArm.ReduceSchoolbookProduct(low, high, middle ^ low ^ high));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateSegment(scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<Vector128<byte>> powers, ref int remainingBlocks, ref Vector128<byte> initial, ref Vector128<ulong> low, ref Vector128<ulong> high, ref Vector128<ulong> middle)
	{
		int completeLength = source.Length & -GHash.BlockSizeInBytes;
		ref byte input = ref source.GetReference();
		ref Vector128<byte> power = ref powers.GetReference();

		for (int offset = 0; offset < completeLength; offset += GHash.BlockSizeInBytes)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref input, (nuint)offset)) ^ initial;
			GHashArm.AccumulateProduct(block, Unsafe.Add(ref power, --remainingBlocks), ref low, ref high, ref middle);
			initial = default;
		}

		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (!remaining.IsEmpty)
		{
			Vector128<byte> finalBlock = LoadPaddedTail(remaining);
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(finalBlock) ^ initial;
			GHashArm.AccumulateProduct(block, Unsafe.Add(ref power, --remainingBlocks), ref low, ref high, ref middle);
			initial = default;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> LoadPaddedTail(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length;
		Debug.Assert(length is > 0 and < GHash.BlockSizeInBytes);
		ref byte input = ref source.GetReference();

		if (length >= 8)
		{
			ulong low = Unsafe.ReadUnaligned<ulong>(ref input);
			ulong high = length is 8 ? 0 : Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref input, length - 8)) >> (16 - length) * 8;
			return Vector128.Create(low, high).AsByte();
		}

		if (length >= 4)
		{
			ulong first = Unsafe.ReadUnaligned<uint>(ref input);
			ulong last = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, length - 4));
			return Vector128.CreateScalar(first | last << (length - 4) * 8).AsByte();
		}

		if (length >= 2)
		{
			uint first = Unsafe.ReadUnaligned<ushort>(ref input);
			uint last = Unsafe.Add(ref input, length - 1);
			return Vector128.CreateScalar((ulong)(first | last << (length - 1) * 8)).AsByte();
		}

		return Vector128.CreateScalar(input);
	}
}
