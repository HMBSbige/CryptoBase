using static CryptoBase.Ciphers.Modes.Gcm.GHashX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal readonly struct GHashVector512PrecomputedKey
{
	private readonly Vector128<byte> _key1;
	private readonly Vector512<byte> _key4321;
	private readonly Vector512<byte> _key8765;
	private readonly Vector512<byte> _key12111009;
	private readonly Vector512<byte> _key16151413;
	private readonly Vector512<byte> _key20191817;
	private readonly Vector512<byte> _key24232221;
	private readonly Vector512<byte> _key28272625;
	private readonly Vector512<byte> _key32313029;
	private readonly Vector512<byte> _key36353433;
	private readonly Vector512<byte> _key40393837;
	private readonly Vector512<byte> _key44434241;
	private readonly Vector512<byte> _key48474645;
	private readonly Vector512<byte> _key52515049;
	private readonly Vector512<byte> _key56555453;
	private readonly Vector512<byte> _key60595857;
	private readonly Vector512<byte> _key64636261;

	internal GHashVector512PrecomputedKey(Vector128<byte> key)
	{
		_key1 = key;
		GetFirstFourPowers(_key1, out Vector256<byte> key21, out Vector256<byte> key43);
		Vector128<byte> key4 = key43.GetLower();
		_key4321 = Vector512.Create(key43, key21);
		Vector512<byte> key4444 = Vector512.Create(key4);
		_key8765 = GFMultiply(_key4321, key4444);

		Vector128<byte> key8 = _key8765.GetLower().GetLower();
		Vector512<byte> key8888 = Vector512.Create(key8);
		_key12111009 = GFMultiply(_key4321, key8888);
		_key16151413 = GFMultiply(_key8765, key8888);

		Vector128<byte> key16 = _key16151413.GetLower().GetLower();
		Vector512<byte> key16161616 = Vector512.Create(key16);
		_key20191817 = GFMultiply(_key4321, key16161616);
		_key24232221 = GFMultiply(_key8765, key16161616);
		_key28272625 = GFMultiply(_key12111009, key16161616);
		_key32313029 = GFMultiply(_key16151413, key16161616);

		Vector128<byte> key32 = _key32313029.GetLower().GetLower();
		Vector512<byte> key32323232 = Vector512.Create(key32);
		_key36353433 = GFMultiply(_key4321, key32323232);
		_key40393837 = GFMultiply(_key8765, key32323232);
		_key44434241 = GFMultiply(_key12111009, key32323232);
		_key48474645 = GFMultiply(_key16151413, key32323232);
		_key52515049 = GFMultiply(_key20191817, key32323232);
		_key56555453 = GFMultiply(_key24232221, key32323232);
		_key60595857 = GFMultiply(_key28272625, key32323232);
		_key64636261 = GFMultiply(_key32313029, key32323232);
	}

	private void AppendBlocks(ref Vector128<byte> accumulatorDestination, scoped ReadOnlySpan<byte> source)
	{
		Vector128<byte> accumulator = accumulatorDestination;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		while (length >= 64 * BlockSize)
		{
			Vector512<uint> lo03;
			Vector512<uint> hi03;
			Vector512<uint> lo47;
			Vector512<uint> hi47;
			Vector512<uint> lo811;
			Vector512<uint> hi811;
			Vector512<uint> lo1215;
			Vector512<uint> hi1215;

			{
				Vector512<byte> x0 = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
				Vector512<byte> x1 = Vector512.LoadUnsafe(ref ptr, 1 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x2 = Vector512.LoadUnsafe(ref ptr, 2 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x3 = Vector512.LoadUnsafe(ref ptr, 3 * 4 * BlockSize).ReverseEndianness128();
				x0 ^= Vector512.Create(Vector256.Create(accumulator, Vector128<byte>.Zero), Vector256<byte>.Zero);

				GFMultiply(_key64636261, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GFMultiply(_key60595857, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GFMultiply(_key56555453, x2, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GFMultiply(_key52515049, x3, out Vector512<uint> lo3, out Vector512<uint> hi3);
				lo03 = lo0 ^ lo1 ^ lo2 ^ lo3;
				hi03 = hi0 ^ hi1 ^ hi2 ^ hi3;
			}

			{
				Vector512<byte> x4 = Vector512.LoadUnsafe(ref ptr, 4 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x5 = Vector512.LoadUnsafe(ref ptr, 5 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x6 = Vector512.LoadUnsafe(ref ptr, 6 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x7 = Vector512.LoadUnsafe(ref ptr, 7 * 4 * BlockSize).ReverseEndianness128();

				GFMultiply(_key48474645, x4, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GFMultiply(_key44434241, x5, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GFMultiply(_key40393837, x6, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GFMultiply(_key36353433, x7, out Vector512<uint> lo3, out Vector512<uint> hi3);
				lo47 = lo0 ^ lo1 ^ lo2 ^ lo3;
				hi47 = hi0 ^ hi1 ^ hi2 ^ hi3;
			}

			{
				Vector512<byte> x8 = Vector512.LoadUnsafe(ref ptr, 8 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x9 = Vector512.LoadUnsafe(ref ptr, 9 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x10 = Vector512.LoadUnsafe(ref ptr, 10 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x11 = Vector512.LoadUnsafe(ref ptr, 11 * 4 * BlockSize).ReverseEndianness128();

				GFMultiply(_key32313029, x8, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GFMultiply(_key28272625, x9, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GFMultiply(_key24232221, x10, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GFMultiply(_key20191817, x11, out Vector512<uint> lo3, out Vector512<uint> hi3);
				lo811 = lo0 ^ lo1 ^ lo2 ^ lo3;
				hi811 = hi0 ^ hi1 ^ hi2 ^ hi3;
			}

			{
				Vector512<byte> x12 = Vector512.LoadUnsafe(ref ptr, 12 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x13 = Vector512.LoadUnsafe(ref ptr, 13 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x14 = Vector512.LoadUnsafe(ref ptr, 14 * 4 * BlockSize).ReverseEndianness128();
				Vector512<byte> x15 = Vector512.LoadUnsafe(ref ptr, 15 * 4 * BlockSize).ReverseEndianness128();

				GFMultiply(_key16151413, x12, out Vector512<uint> lo0, out Vector512<uint> hi0);
				GFMultiply(_key12111009, x13, out Vector512<uint> lo1, out Vector512<uint> hi1);
				GFMultiply(_key8765, x14, out Vector512<uint> lo2, out Vector512<uint> hi2);
				GFMultiply(_key4321, x15, out Vector512<uint> lo3, out Vector512<uint> hi3);
				lo1215 = lo0 ^ lo1 ^ lo2 ^ lo3;
				hi1215 = hi0 ^ hi1 ^ hi2 ^ hi3;
			}

			accumulator = ReduceTo128(lo03 ^ lo47 ^ lo811 ^ lo1215, hi03 ^ hi47 ^ hi811 ^ hi1215);
			ptr = ref Unsafe.Add(ref ptr, 64 * BlockSize);
			length -= 64 * BlockSize;
		}

		if (length >= 32 * BlockSize)
		{
			Vector512<byte> x0 = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
			Vector512<byte> x1 = Vector512.LoadUnsafe(ref ptr, 1 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x2 = Vector512.LoadUnsafe(ref ptr, 2 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x3 = Vector512.LoadUnsafe(ref ptr, 3 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x4 = Vector512.LoadUnsafe(ref ptr, 4 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x5 = Vector512.LoadUnsafe(ref ptr, 5 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x6 = Vector512.LoadUnsafe(ref ptr, 6 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x7 = Vector512.LoadUnsafe(ref ptr, 7 * 4 * BlockSize).ReverseEndianness128();

			x0 = Avx512F.InsertVector128(x0, x0.GetLower().GetLower() ^ accumulator, 0);

			GFMultiply(_key32313029, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
			GFMultiply(_key28272625, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
			GFMultiply(_key24232221, x2, out Vector512<uint> lo2, out Vector512<uint> hi2);
			GFMultiply(_key20191817, x3, out Vector512<uint> lo3, out Vector512<uint> hi3);
			GFMultiply(_key16151413, x4, out Vector512<uint> lo4, out Vector512<uint> hi4);
			GFMultiply(_key12111009, x5, out Vector512<uint> lo5, out Vector512<uint> hi5);
			GFMultiply(_key8765, x6, out Vector512<uint> lo6, out Vector512<uint> hi6);
			GFMultiply(_key4321, x7, out Vector512<uint> lo7, out Vector512<uint> hi7);

			accumulator = ReduceTo128(lo0 ^ lo1 ^ lo2 ^ lo3 ^ lo4 ^ lo5 ^ lo6 ^ lo7, hi0 ^ hi1 ^ hi2 ^ hi3 ^ hi4 ^ hi5 ^ hi6 ^ hi7);

			ptr = ref Unsafe.Add(ref ptr, 32 * BlockSize);
			length -= 32 * BlockSize;
		}

		if (length >= 16 * BlockSize)
		{
			Vector512<byte> x0 = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
			Vector512<byte> x1 = Vector512.LoadUnsafe(ref ptr, 1 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x2 = Vector512.LoadUnsafe(ref ptr, 2 * 4 * BlockSize).ReverseEndianness128();
			Vector512<byte> x3 = Vector512.LoadUnsafe(ref ptr, 3 * 4 * BlockSize).ReverseEndianness128();

			x0 = Avx512F.InsertVector128(x0, x0.GetLower().GetLower() ^ accumulator, 0);

			GFMultiply(_key16151413, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
			GFMultiply(_key12111009, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
			GFMultiply(_key8765, x2, out Vector512<uint> lo2, out Vector512<uint> hi2);
			GFMultiply(_key4321, x3, out Vector512<uint> lo3, out Vector512<uint> hi3);
			accumulator = ReduceTo128(lo0 ^ lo1 ^ lo2 ^ lo3, hi0 ^ hi1 ^ hi2 ^ hi3);

			ptr = ref Unsafe.Add(ref ptr, 16 * BlockSize);
			length -= 16 * BlockSize;
		}

		if (length >= 8 * BlockSize)
		{
			Vector512<byte> x0 = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
			Vector512<byte> x1 = Vector512.LoadUnsafe(ref ptr, 1 * 4 * BlockSize).ReverseEndianness128();

			x0 = Avx512F.InsertVector128(x0, x0.GetLower().GetLower() ^ accumulator, 0);

			GFMultiply(_key8765, x0, out Vector512<uint> lo0, out Vector512<uint> hi0);
			GFMultiply(_key4321, x1, out Vector512<uint> lo1, out Vector512<uint> hi1);
			accumulator = ReduceTo128(lo0 ^ lo1, hi0 ^ hi1);

			ptr = ref Unsafe.Add(ref ptr, 8 * BlockSize);
			length -= 8 * BlockSize;
		}

		if (length >= 4 * BlockSize)
		{
			Vector512<byte> blocks = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
			blocks = Avx512F.InsertVector128(blocks, blocks.GetLower().GetLower() ^ accumulator, 0);

			GFMultiply(_key4321, blocks, out Vector512<uint> lo, out Vector512<uint> hi);
			accumulator = ReduceTo128(lo, hi);

			ptr = ref Unsafe.Add(ref ptr, 4 * BlockSize);
			length -= 4 * BlockSize;
		}

		AppendSequential(ref accumulator, in _key1, MemoryMarshal.CreateReadOnlySpan(ref ptr, length));

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
		int tailBlocks = (completeBlocks & 63) switch
		{
			31 => 32,
			63 => 64,
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
		Vector512<byte> blocks = Vector512.LoadUnsafe(ref ptr).ReverseEndianness128();
		blocks = Avx512F.InsertVector128(blocks, blocks.GetLower().GetLower() ^ accumulator, 0);
		Vector512<byte> firstKey = blockCount is 64 ? _key64636261 : _key32313029;
		GFMultiply(firstKey, blocks, out Vector512<uint> lo, out Vector512<uint> hi);
		nuint offset = 4 * BlockSize;

		if (blockCount is 64)
		{
			AppendFoldedBlocks(ref ptr, offset, _key60595857, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key56555453, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key52515049, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key48474645, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key44434241, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key40393837, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key36353433, ref lo, ref hi);
			offset += 4 * BlockSize;
			AppendFoldedBlocks(ref ptr, offset, _key32313029, ref lo, ref hi);
			offset += 4 * BlockSize;
		}

		AppendFoldedBlocks(ref ptr, offset, _key28272625, ref lo, ref hi);
		offset += 4 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key24232221, ref lo, ref hi);
		offset += 4 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key20191817, ref lo, ref hi);
		offset += 4 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key16151413, ref lo, ref hi);
		offset += 4 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key12111009, ref lo, ref hi);
		offset += 4 * BlockSize;
		AppendFoldedBlocks(ref ptr, offset, _key8765, ref lo, ref hi);
		offset += 4 * BlockSize;

		Vector256<byte> lastTwo = Vector256.LoadUnsafe(ref ptr, offset);
		Vector128<byte> lastSource = Vector128.LoadUnsafe(ref ptr, offset + 2 * BlockSize);
		Vector512<byte> lastBlocks = Vector512.Create(lastTwo, Vector256.Create(lastSource, finalBlock)).ReverseEndianness128();
		GFMultiply(_key4321, lastBlocks, out Vector512<uint> lastLo, out Vector512<uint> lastHi);
		accumulator = ReduceTo128(lo ^ lastLo, hi ^ lastHi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AppendFoldedBlocks(ref byte ptr, nuint offset, Vector512<byte> key, ref Vector512<uint> lo, ref Vector512<uint> hi)
	{
		Vector512<byte> blocks = Vector512.LoadUnsafe(ref ptr, offset).ReverseEndianness128();
		GFMultiply(key, blocks, out Vector512<uint> nextLo, out Vector512<uint> nextHi);
		lo ^= nextLo;
		hi ^= nextHi;
	}
}
