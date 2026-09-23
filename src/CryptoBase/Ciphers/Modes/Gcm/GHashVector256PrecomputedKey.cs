using static CryptoBase.Ciphers.Modes.Gcm.GHashX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal readonly struct GHashVector256PrecomputedKey
{
	private readonly Vector128<byte> _key1;
	private readonly Vector256<byte> _key21;
	private readonly Vector256<byte> _keyK21;
	private readonly Vector256<byte> _key43;
	private readonly Vector256<byte> _keyK43;
	private readonly Vector256<byte> _key65;
	private readonly Vector256<byte> _keyK65;
	private readonly Vector256<byte> _key87;
	private readonly Vector256<byte> _keyK87;
	private readonly Vector256<byte> _key1009;
	private readonly Vector256<byte> _keyK1009;
	private readonly Vector256<byte> _key1211;
	private readonly Vector256<byte> _keyK1211;
	private readonly Vector256<byte> _key1413;
	private readonly Vector256<byte> _keyK1413;
	private readonly Vector256<byte> _key1615;
	private readonly Vector256<byte> _keyK1615;

	internal GHashVector256PrecomputedKey(Vector128<byte> key)
	{
		_key1 = key;
		Vector128<byte> preparedKey1 = PrepareKey(key);
		Vector128<byte> preparedKeyK1 = GetReductionKey(preparedKey1);
		Vector128<byte> preparedKey2 = GFMultiplyPrepared(preparedKey1, preparedKey1, preparedKeyK1);
		_key21 = Vector256.Create(preparedKey2, preparedKey1);
		_keyK21 = GetReductionKey(_key21);

		Vector256<byte> preparedKey22 = Vector256.Create(preparedKey2);
		_key43 = GFMultiplyPrepared(_key21, preparedKey22, GetReductionKey(preparedKey22));
		_keyK43 = GetReductionKey(_key43);
		Vector128<byte> key4 = _key43.GetLower();

		Vector256<byte> key44 = Vector256.Create(key4);
		Vector256<byte> keyK44 = GetReductionKey(key44);
		_key65 = GFMultiplyPrepared(_key21, key44, keyK44);
		_keyK65 = GetReductionKey(_key65);
		_key87 = GFMultiplyPrepared(_key43, key44, keyK44);
		_keyK87 = GetReductionKey(_key87);

		Vector128<byte> key8 = _key87.GetLower();
		Vector256<byte> key88 = Vector256.Create(key8);
		Vector256<byte> keyK88 = GetReductionKey(key88);
		_key1009 = GFMultiplyPrepared(_key21, key88, keyK88);
		_keyK1009 = GetReductionKey(_key1009);
		_key1211 = GFMultiplyPrepared(_key43, key88, keyK88);
		_keyK1211 = GetReductionKey(_key1211);
		_key1413 = GFMultiplyPrepared(_key65, key88, keyK88);
		_keyK1413 = GetReductionKey(_key1413);
		_key1615 = GFMultiplyPrepared(_key87, key88, keyK88);
		_keyK1615 = GetReductionKey(_key1615);
	}

	private void AppendBlocks(ref Vector128<byte> accumulatorDestination, scoped ReadOnlySpan<byte> source)
	{
		Vector128<byte> accumulator = accumulatorDestination;
		int offset = 0;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		while (length >= 16 * BlockSize)
		{
			Vector256<byte> x0 = Vector256.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector256<byte> x1 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 1 * 2 * BlockSize)).ReverseEndianness128();
			Vector256<byte> x2 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 2 * 2 * BlockSize)).ReverseEndianness128();
			Vector256<byte> x3 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 3 * 2 * BlockSize)).ReverseEndianness128();
			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref x0);
			firstBlock ^= accumulator;

			GFMultiplyPreparedUnreduced(x0, _key1615, _keyK1615, out Vector256<byte> lo, out Vector256<byte> hi);
			GFMultiplyPreparedUnreduced(x1, _key1413, _keyK1413, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x2, _key1211, _keyK1211, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x3, _key1009, _keyK1009, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;

			x0 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 4 * 2 * BlockSize)).ReverseEndianness128();
			x1 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 5 * 2 * BlockSize)).ReverseEndianness128();
			x2 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 6 * 2 * BlockSize)).ReverseEndianness128();
			x3 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 7 * 2 * BlockSize)).ReverseEndianness128();
			GFMultiplyPreparedUnreduced(x0, _key87, _keyK87, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x1, _key65, _keyK65, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x2, _key43, _keyK43, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x3, _key21, _keyK21, out nextLo, out nextHi);
			accumulator = ReducePreparedTo128(lo ^ nextLo, hi ^ nextHi);

			offset += 16 * BlockSize;
			length -= 16 * BlockSize;
		}

		if (length >= 8 * BlockSize)
		{
			Vector256<byte> x0 = Vector256.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector256<byte> x1 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 1 * 2 * BlockSize)).ReverseEndianness128();
			Vector256<byte> x2 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 2 * 2 * BlockSize)).ReverseEndianness128();
			Vector256<byte> x3 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 3 * 2 * BlockSize)).ReverseEndianness128();

			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref x0);
			firstBlock ^= accumulator;

			GFMultiplyPreparedUnreduced(x0, _key87, _keyK87, out Vector256<byte> lo, out Vector256<byte> hi);
			GFMultiplyPreparedUnreduced(x1, _key65, _keyK65, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x2, _key43, _keyK43, out nextLo, out nextHi);
			lo ^= nextLo;
			hi ^= nextHi;
			GFMultiplyPreparedUnreduced(x3, _key21, _keyK21, out nextLo, out nextHi);
			accumulator = ReducePreparedTo128(lo ^ nextLo, hi ^ nextHi);

			offset += 8 * BlockSize;
			length -= 8 * BlockSize;
		}

		if (length >= 4 * BlockSize)
		{
			Vector256<byte> x0 = Vector256.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			Vector256<byte> x1 = Vector256.LoadUnsafe(ref ptr, (nuint)(offset + 1 * 2 * BlockSize)).ReverseEndianness128();

			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref x0);
			firstBlock ^= accumulator;

			GFMultiplyPreparedUnreduced(x0, _key43, _keyK43, out Vector256<byte> lo, out Vector256<byte> hi);
			GFMultiplyPreparedUnreduced(x1, _key21, _keyK21, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
			accumulator = ReducePreparedTo128(lo ^ nextLo, hi ^ nextHi);

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length >= 2 * BlockSize)
		{
			Vector256<byte> blocks = Vector256.LoadUnsafe(ref ptr, (nuint)offset).ReverseEndianness128();
			ref Vector128<byte> firstBlock = ref Unsafe.As<Vector256<byte>, Vector128<byte>>(ref blocks);
			firstBlock ^= accumulator;

			GFMultiplyPreparedUnreduced(blocks, _key21, _keyK21, out Vector256<byte> lo, out Vector256<byte> hi);
			accumulator = ReducePreparedTo128(lo, hi);

			offset += 2 * BlockSize;
			length -= 2 * BlockSize;
		}

		AppendSequential(ref accumulator, in _key1, source.Slice(offset, length));

		accumulatorDestination = accumulator;
	}

	internal void AppendPaddedSegment(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock)
	{
		int completeLength = source.Length & -BlockSize;
		ReadOnlySpan<byte> remaining = source.Slice(completeLength);

		if (remaining.IsEmpty)
		{
			if (completeLength is not 0)
			{
				AppendBlocks(ref accumulator, source);
			}

			return;
		}

		finalBlock = default;
		remaining.CopyTo(finalBlock.AsSpan());

		int completeBlocks = completeLength / BlockSize;
		int tailBlocks = (completeBlocks & 15) switch
		{
			7 => 8,
			15 => 16,
			_ => 0
		};

		if (tailBlocks is not 0)
		{
			int prefixLength = completeLength - (tailBlocks - 1) * BlockSize;
			AppendBlocks(ref accumulator, source.Slice(0, prefixLength));
			AppendFoldedTail(ref accumulator, source.Slice(prefixLength, (tailBlocks - 1) * BlockSize), ref finalBlock, tailBlocks);
			return;
		}

		if (completeLength is not 0)
		{
			AppendBlocks(ref accumulator, source.Slice(0, completeLength));
		}

		AppendBlocks(ref accumulator, finalBlock.AsReadOnlySpan());
	}

	private void AppendFoldedTail(ref Vector128<byte> accumulator, scoped ReadOnlySpan<byte> source, ref Vector128<byte> finalBlock, int blockCount)
	{
		ref byte ptr = ref source.GetReference();
		Vector256<byte> blocks = Vector256.LoadUnsafe(ref ptr).ReverseEndianness128();
		blocks = Vector256.Create(blocks.GetLower() ^ accumulator, blocks.GetUpper());
		Vector256<byte> firstKey = blockCount is 16 ? _key1615 : _key87;
		Vector256<byte> firstReductionKey = blockCount is 16 ? _keyK1615 : _keyK87;
		GFMultiplyPreparedUnreduced(blocks, firstKey, firstReductionKey, out Vector256<byte> lo, out Vector256<byte> hi);
		nuint offset = 2 * BlockSize;

		if (blockCount is 16)
		{
			AppendFoldedBlocks(ref ptr, offset, _key1413, _keyK1413, ref lo, ref hi);
			offset += 2 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key1211, _keyK1211, ref lo, ref hi);
			offset += 2 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key1009, _keyK1009, ref lo, ref hi);
			offset += 2 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key87, _keyK87, ref lo, ref hi);
			offset += 2 * BlockSize;
		}

		AppendFoldedBlocks(ref ptr, offset, _key65, _keyK65, ref lo, ref hi);
		offset += 2 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key43, _keyK43, ref lo, ref hi);
		offset += 2 * BlockSize;

		Vector128<byte> lastSource = Vector128.LoadUnsafe(ref ptr, offset);
		Vector256<byte> lastBlocks = Vector256.Create(lastSource, finalBlock).ReverseEndianness128();
		GFMultiplyPreparedUnreduced(lastBlocks, _key21, _keyK21, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
		accumulator = ReducePreparedTo128(lo ^ nextLo, hi ^ nextHi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendFoldedBlocks(ref byte ptr, nuint offset, Vector256<byte> key, Vector256<byte> reductionKey, ref Vector256<byte> lo, ref Vector256<byte> hi)
	{
		Vector256<byte> blocks = Vector256.LoadUnsafe(ref ptr, offset).ReverseEndianness128();
		GFMultiplyPreparedUnreduced(blocks, key, reductionKey, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
		lo ^= nextLo;
		hi ^= nextHi;
	}
}
