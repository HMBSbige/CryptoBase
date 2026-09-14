using static CryptoBase.Ciphers.Modes.Gcm.GHashArm;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashArmFoldedState
{
	private readonly Vector128<byte> _key1;
	private readonly Vector128<byte> _key2;
	private readonly Vector128<byte> _key3;
	private readonly Vector128<byte> _key4;
	private readonly Vector128<byte> _key5;
	private readonly Vector128<byte> _key6;
	private readonly Vector128<byte> _key7;
	private readonly Vector128<byte> _key8;
	private Vector128<byte> _accumulator;

	internal GHashArmFoldedState(Vector128<byte> key, Vector128<byte> accumulator)
	{
		_key1 = key;
		_key2 = GFSquare(_key1);
		_key3 = GFMultiply(_key2, _key1);
		_key4 = GFSquare(_key2);
		_key5 = GFMultiply(_key4, _key1);
		_key6 = GFMultiply(_key4, _key2);
		_key7 = GFMultiply(_key4, _key3);
		_key8 = GFSquare(_key4);
		_accumulator = accumulator;
	}

	private void AppendBlocks(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length;
		ref byte sourceRef = ref source.GetReference();

		while (length >= 8 * BlockSize)
		{
			Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 1 * BlockSize));
			GFMultiplyUnreduced(value, _key7, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 2 * BlockSize));
			AccumulateProduct(value, _key6, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 3 * BlockSize));
			AccumulateProduct(value, _key5, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 4 * BlockSize));
			AccumulateProduct(value, _key4, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 5 * BlockSize));
			AccumulateProduct(value, _key3, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 6 * BlockSize));
			AccumulateProduct(value, _key2, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 7 * BlockSize));
			AccumulateProduct(value, _key1, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef)) ^ _accumulator;
			AccumulateProduct(value, _key8, ref lowProduct, ref highProduct, ref middleProduct);
			FinishFold(lowProduct, highProduct, middleProduct);

			sourceRef = ref Unsafe.Add(ref sourceRef, 8 * BlockSize);
			length -= 8 * BlockSize;
		}

		while (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef));
			Vector128<byte> x1 = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 1 * BlockSize));
			Vector128<byte> x2 = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 2 * BlockSize));
			Vector128<byte> x3 = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 3 * BlockSize));
			x0 ^= _accumulator;

			GFMultiplyUnreduced(x1, _key3, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
			AccumulateProduct(x2, _key2, ref lowProduct, ref highProduct, ref middleProduct);
			AccumulateProduct(x3, _key1, ref lowProduct, ref highProduct, ref middleProduct);
			AccumulateProduct(x0, _key4, ref lowProduct, ref highProduct, ref middleProduct);
			FinishFold(lowProduct, highProduct, middleProduct);

			sourceRef = ref Unsafe.Add(ref sourceRef, 4 * BlockSize);
			length -= 4 * BlockSize;
		}

		while (length >= BlockSize)
		{
			Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef));
			_accumulator = GFMultiply(block ^ _accumulator, _key1);
			sourceRef = ref Unsafe.Add(ref sourceRef, BlockSize);
			length -= BlockSize;
		}
	}

	internal void AppendPaddedSegment(scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -BlockSize;
		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			AppendBlocks(source);
			return;
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());
		ReadOnlySpan<byte> final = finalBlock.AsReadOnlySpan();
		ref byte finalRef = ref final.GetReference();

		int completeBlockCount = completeLength / BlockSize;
		int foldedBlockCount = (completeBlockCount & 7) + 1;

		if (foldedBlockCount > 1)
		{
			int prefixLength = completeLength - (foldedBlockCount - 1) * BlockSize;
			AppendBlocks(source.Slice(0, prefixLength));
			ref byte tailRef = ref source.Slice(prefixLength).GetReference();

			switch (foldedBlockCount)
			{
				case 2:
				{
					AppendTwo(ref tailRef, ref finalRef);
					break;
				}
				case 4:
				{
					AppendFour(ref tailRef, ref finalRef);
					break;
				}
				case 8:
				{
					AppendEight(ref tailRef, ref finalRef);
					break;
				}
				default:
				{
					AppendFoldedTail(ref tailRef, ref finalRef, foldedBlockCount);
					break;
				}
			}

			return;
		}

		AppendBlocks(source.Slice(0, completeLength));
		AppendBlocks(finalBlock.AsReadOnlySpan());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendEight(ref byte source, ref byte lastSource)
	{
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 1 * BlockSize));
		GFMultiplyUnreduced(value, _key7, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 2 * BlockSize));
		AccumulateProduct(value, _key6, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 3 * BlockSize));
		AccumulateProduct(value, _key5, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 4 * BlockSize));
		AccumulateProduct(value, _key4, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 5 * BlockSize));
		AccumulateProduct(value, _key3, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 6 * BlockSize));
		AccumulateProduct(value, _key2, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		AccumulateProduct(value, _key1, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _key8, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendFour(ref byte source, ref byte lastSource)
	{
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 1 * BlockSize));
		GFMultiplyUnreduced(value, _key3, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 2 * BlockSize));
		AccumulateProduct(value, _key2, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		AccumulateProduct(value, _key1, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _key4, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendTwo(ref byte source, ref byte lastSource)
	{
		Vector128<byte> last = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		GFMultiplyUnreduced(last, _key1, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _key2, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendFoldedTail(ref byte source, ref byte lastSource, int blockCount)
	{
		Debug.Assert(blockCount is 3 or 5 or 6 or 7);
		Vector128<byte> last = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		GFMultiplyUnreduced(last, _key1, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);

		ref byte block = ref Unsafe.Add(ref source, (blockCount - 2) * BlockSize);
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
		AccumulateProduct(value, _key2, ref lowProduct, ref highProduct, ref middleProduct);

		if (blockCount > 3)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _key3, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 4)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _key4, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 5)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _key5, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 6)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _key6, ref lowProduct, ref highProduct, ref middleProduct);
		}

		Vector128<byte> first = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		Vector128<byte> firstKey = blockCount switch
		{
			3 => _key3,
			5 => _key5,
			6 => _key6,
			_ => _key7
		};
		AccumulateProduct(first, firstKey, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void FinishFold(Vector128<ulong> lowProduct, Vector128<ulong> highProduct, Vector128<ulong> middleProduct)
	{
		AssembleProduct(lowProduct, highProduct, middleProduct, out Vector128<uint> reducedLow, out Vector128<uint> reducedHigh);
		_accumulator = Reduce(reducedLow, reducedHigh);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly Vector128<byte> GetAccumulator()
	{
		return _accumulator;
	}
}
