using static CryptoBase.Ciphers.Modes.Gcm.GHashArm;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal ref struct GHashArmFoldedState : IDisposable
{
	private readonly ref readonly GHashArmPrecomputedKey _powers;
	private Vector128<byte> _accumulator;

	internal GHashArmFoldedState(in GHashArmPrecomputedKey powers, Vector128<byte> accumulator)
	{
		_powers = ref powers;
		_accumulator = accumulator;
	}

	public void Dispose()
	{
		_accumulator.ZeroMemory();
	}

	private void AppendBlocks(scoped ReadOnlySpan<byte> source)
	{
		int length = source.Length;
		ref byte sourceRef = ref MemoryMarshal.GetReference(source);

		while (length >= 8 * BlockSize)
		{
			Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 1 * BlockSize));
			GFMultiplyUnreduced(value, _powers.Key7, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 2 * BlockSize));
			AccumulateProduct(value, _powers.Key6, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 3 * BlockSize));
			AccumulateProduct(value, _powers.Key5, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 4 * BlockSize));
			AccumulateProduct(value, _powers.Key4, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 5 * BlockSize));
			AccumulateProduct(value, _powers.Key3, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 6 * BlockSize));
			AccumulateProduct(value, _powers.Key2, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef, 7 * BlockSize));
			AccumulateProduct(value, _powers.Key1, ref lowProduct, ref highProduct, ref middleProduct);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef)) ^ _accumulator;
			AccumulateProduct(value, _powers.Key8, ref lowProduct, ref highProduct, ref middleProduct);
			FinishFold(lowProduct, highProduct, middleProduct);

			sourceRef = ref Unsafe.Add(ref sourceRef, 8 * BlockSize);
			length -= 8 * BlockSize;
		}

		if (length is 0)
		{
			return;
		}

		ref byte lastSource = ref Unsafe.Add(ref sourceRef, length - BlockSize);

		switch (length / BlockSize)
		{
			case 1:
			{
				Vector128<byte> block = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref sourceRef));
				_accumulator = GFMultiply(block ^ _accumulator, _powers.Key1);
				break;
			}
			case 2:
			{
				AppendTwo(ref sourceRef, ref lastSource);
				break;
			}
			case 4:
			{
				AppendFour(ref sourceRef, ref lastSource);
				break;
			}
			default:
			{
				AppendFoldedTail(ref sourceRef, ref lastSource, length / BlockSize);
				break;
			}
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

		finalBlock = GHash.PadFinalBlock(remaining);
		ReadOnlySpan<byte> final = finalBlock.AsReadOnlySpan();
		ref byte finalRef = ref MemoryMarshal.GetReference(final);

		int completeBlockCount = completeLength / BlockSize;
		int foldedBlockCount = (completeBlockCount & 7) + 1;

		if (foldedBlockCount > 1)
		{
			int prefixLength = completeLength - (foldedBlockCount - 1) * BlockSize;
			AppendBlocks(source.Slice(0, prefixLength));
			ref byte tailRef = ref MemoryMarshal.GetReference(source.Slice(prefixLength));

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

	[MethodImpl(MethodImplOptions.NoInlining)]
	private void AppendEight(ref byte source, ref byte lastSource)
	{
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 1 * BlockSize));
		GFMultiplyUnreduced(value, _powers.Key7, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 2 * BlockSize));
		AccumulateProduct(value, _powers.Key6, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 3 * BlockSize));
		AccumulateProduct(value, _powers.Key5, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 4 * BlockSize));
		AccumulateProduct(value, _powers.Key4, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 5 * BlockSize));
		AccumulateProduct(value, _powers.Key3, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 6 * BlockSize));
		AccumulateProduct(value, _powers.Key2, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		AccumulateProduct(value, _powers.Key1, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _powers.Key8, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendFour(ref byte source, ref byte lastSource)
	{
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 1 * BlockSize));
		GFMultiplyUnreduced(value, _powers.Key3, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source, 2 * BlockSize));
		AccumulateProduct(value, _powers.Key2, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		AccumulateProduct(value, _powers.Key1, ref lowProduct, ref highProduct, ref middleProduct);
		value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _powers.Key4, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendTwo(ref byte source, ref byte lastSource)
	{
		Vector128<byte> last = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		GFMultiplyUnreduced(last, _powers.Key1, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		AccumulateProduct(value, _powers.Key2, ref lowProduct, ref highProduct, ref middleProduct);
		FinishFold(lowProduct, highProduct, middleProduct);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void AppendFoldedTail(ref byte source, ref byte lastSource, int blockCount)
	{
		Debug.Assert(blockCount is 3 or 5 or 6 or 7);
		Vector128<byte> last = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref lastSource));
		GFMultiplyUnreduced(last, _powers.Key1, out Vector128<ulong> lowProduct, out Vector128<ulong> highProduct, out Vector128<ulong> middleProduct);

		ref byte block = ref Unsafe.Add(ref source, (blockCount - 2) * BlockSize);
		Vector128<byte> value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
		AccumulateProduct(value, _powers.Key2, ref lowProduct, ref highProduct, ref middleProduct);

		if (blockCount > 3)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _powers.Key3, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 4)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _powers.Key4, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 5)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _powers.Key5, ref lowProduct, ref highProduct, ref middleProduct);
		}

		if (blockCount > 6)
		{
			block = ref Unsafe.Subtract(ref block, BlockSize);
			value = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref block));
			AccumulateProduct(value, _powers.Key6, ref lowProduct, ref highProduct, ref middleProduct);
		}

		Vector128<byte> first = AdvSimd.Arm64.ReverseElementBits(Vector128.LoadUnsafe(ref source)) ^ _accumulator;
		Vector128<byte> firstKey = blockCount switch
		{
			3 => _powers.Key3,
			5 => _powers.Key5,
			6 => _powers.Key6,
			_ => _powers.Key7
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
