using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes up to eight inputs with the state of each held as four rows, as Blake3Vector128.Compress does: four inputs to a group of 512-bit rows, input i of a group in 128-bit block i. A group of fewer inputs keeps its last one in block 3 and rehashes input 0 in the blocks between.
// The column layout issues four rotations per step at once, which two rotation pipes take two cycles to start; where vector operations take two cycles and the dependency chain sets the pace, as on Zen 5, every queued rotation stretches the chain. A row step issues one rotation per group instead.
internal readonly struct Blake3Vector512Rows : IBlake3Kernel
{
	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512F.IsSupported;

	// Preferred over the column kernels for two to eight inputs on Zen 5 only.
	internal static readonly bool IsPreferred = IsSupported && CpuIdUtils.IsAmdZen5();

	public static int Degree => 8;

	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length > 8 * ChunkLength; length -= 8 * ChunkLength)
		{
			Hash8(ref input, 8, 0, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 8 * ChunkLength);
			output = ref Unsafe.Add(ref output, 8 * OutLength);
			counter += 8;
		}

		nuint count = length / ChunkLength;
		nuint tailLength = length % ChunkLength;

		// A partial last chunk takes a lane of its own when a group has one spare, or when its blocks would take longer on their own than the lane: next to one full chunk, which the scalar compressor hashes faster alone, from twelve blocks; next to four, which then take two groups, from two.
		bool rides = count switch
		{
			0 => false,
			1 => tailLength > 11 * BlockLength,
			4 => tailLength > BlockLength,
			_ => tailLength is not 0
		};

		if (rides)
		{
			HashLast(ref input, count + 1, tailLength, in key, counter, flags, ref output);
			return;
		}

		if (count is not 0)
		{
			HashLast(ref input, count, 0, in key, counter, flags, ref output);
		}

		if (tailLength is not 0)
		{
			Blake3Compressor.HashChunk(ref Unsafe.Add(ref input, count * ChunkLength), tailLength, in key, counter + count, flags, ref Unsafe.Add(ref output, count * OutLength));
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		for (; count > 8; count -= 8)
		{
			Hash8(ref input, 8, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
			input = ref Unsafe.Add(ref input, 8 * BlockLength);
			output = ref Unsafe.Add(ref output, 8 * OutLength);
		}

		if (count > 4)
		{
			Hash8(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (count > 1)
		{
			Hash(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (count is 1)
		{
			Blake3Compressor.Compress(in key, ref input, BlockLength, 0, flags | Blake3Flags.Parent, ref output);
		}
	}

	private static void HashLast(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		if (count > 4)
		{
			Hash8(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else if (count > 1)
		{
			Hash(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else
		{
			Blake3Compressor.HashChunk(ref input, ChunkLength, in key, counter, flags, ref output);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Debug.Assert(count is > 1 and <= 4);

		bool chunks = (flags & Blake3Flags.Parent) is 0;
		nuint blockCount = chunks ? (nuint)ChunkBlocks : 1;
		nuint stride = blockCount * BlockLength;
		uint startFlags = chunks ? Blake3Flags.ChunkStart : 0;
		uint endFlags = chunks ? Blake3Flags.ChunkEnd : 0;

		nuint offset1 = count > 2 ? stride : 0;
		nuint offset2 = count > 3 ? 2 * stride : 0;
		Unsafe.SkipInit(out InlineArray64<byte> lastBlock);
		Blake3LastLane last = new(ref Unsafe.Add(ref input, (count - 1) * stride), blockCount, tailLength, ref lastBlock);

		Vector512<uint> h0 = Vector512.Broadcast(Vector128.LoadUnsafe(in key));
		Vector512<uint> h1 = Vector512.Broadcast(Vector128.LoadUnsafe(in key, 4));
		Vector512<ulong> counters = Vector512.Create(counter);

		if (chunks)
		{
			counters += Vector512.Create(0UL, 0, 1, 0, 2, 0, count - 1, 0);
		}

		uint blockFlags = flags | startFlags;

		do
		{
			LoadMessage(ref input, ref Unsafe.Add(ref input, offset1), ref Unsafe.Add(ref input, offset2), ref last.Next(blockCount), out Vector512<uint> m0, out Vector512<uint> m1, out Vector512<uint> m2, out Vector512<uint> m3);

			uint rowFlags = blockCount is 1 ? blockFlags | endFlags : blockFlags;
			Vector512<uint> row3 = CreateRow3(counters, rowFlags);

			if (blockCount <= last.TailBlocks)
			{
				JoinLastLane(ref h0, ref h1, ref row3, in key, in last, blockCount, rowFlags);
			}

			Vector512<uint> row0 = h0;
			Vector512<uint> row1 = h1;
			Vector512<uint> row2 = Vector512.Create(IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3);

			Rounds(ref row0, ref row1, ref row2, ref row3, m0, m1, m2, m3);

			h0 = row0 ^ row2;
			h1 = row1 ^ row3;
			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		StoreChainingValues(h0, h1, count, ref output);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash8(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Debug.Assert(count is > 4 and <= 8);

		bool chunks = (flags & Blake3Flags.Parent) is 0;
		nuint blockCount = chunks ? (nuint)ChunkBlocks : 1;
		nuint stride = blockCount * BlockLength;
		uint startFlags = chunks ? Blake3Flags.ChunkStart : 0;
		uint endFlags = chunks ? Blake3Flags.ChunkEnd : 0;

		nuint offset4 = count > 5 ? 4 * stride : 0;
		nuint offset5 = count > 6 ? 5 * stride : 0;
		nuint offset6 = count > 7 ? 6 * stride : 0;
		Unsafe.SkipInit(out InlineArray64<byte> lastBlock);
		Blake3LastLane last = new(ref Unsafe.Add(ref input, (count - 1) * stride), blockCount, tailLength, ref lastBlock);

		Vector512<uint> h0 = Vector512.Broadcast(Vector128.LoadUnsafe(in key));
		Vector512<uint> h1 = Vector512.Broadcast(Vector128.LoadUnsafe(in key, 4));
		Vector512<uint> h2 = h0;
		Vector512<uint> h3 = h1;
		Vector512<ulong> counters0 = Vector512.Create(counter);
		Vector512<ulong> counters1 = counters0;

		if (chunks)
		{
			counters0 += Vector512.Create(0UL, 0, 1, 0, 2, 0, 3, 0);
			counters1 += Vector512.Create(4UL, 0, 5, 0, 6, 0, count - 1, 0);
		}

		uint blockFlags = flags | startFlags;

		do
		{
			LoadMessage(ref input, ref Unsafe.Add(ref input, stride), ref Unsafe.Add(ref input, 2 * stride), ref Unsafe.Add(ref input, 3 * stride), out Vector512<uint> m0, out Vector512<uint> m1, out Vector512<uint> m2, out Vector512<uint> m3);
			LoadMessage(ref Unsafe.Add(ref input, offset4), ref Unsafe.Add(ref input, offset5), ref Unsafe.Add(ref input, offset6), ref last.Next(blockCount), out Vector512<uint> n0, out Vector512<uint> n1, out Vector512<uint> n2, out Vector512<uint> n3);

			uint rowFlags = blockCount is 1 ? blockFlags | endFlags : blockFlags;
			Vector512<uint> row3 = CreateRow3(counters0, rowFlags);
			Vector512<uint> row7 = CreateRow3(counters1, rowFlags);

			if (blockCount <= last.TailBlocks)
			{
				JoinLastLane(ref h2, ref h3, ref row7, in key, in last, blockCount, rowFlags);
			}

			Vector512<uint> row0 = h0;
			Vector512<uint> row1 = h1;
			Vector512<uint> row2 = Vector512.Create(IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3);
			Vector512<uint> row4 = h2;
			Vector512<uint> row5 = h3;
			Vector512<uint> row6 = row2;

			Rounds(ref row0, ref row1, ref row2, ref row3, ref row4, ref row5, ref row6, ref row7, m0, m1, m2, m3, n0, n1, n2, n3);

			h0 = row0 ^ row2;
			h1 = row1 ^ row3;
			h2 = row4 ^ row6;
			h3 = row5 ^ row7;
			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		StoreChainingValues(h0, h1, 4, ref output);
		StoreChainingValues(h2, h3, count - 4, ref Unsafe.Add(ref output, 4 * OutLength));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void JoinLastLane(ref Vector512<uint> h0, ref Vector512<uint> h1, ref Vector512<uint> row3, ref readonly uint key, ref readonly Blake3LastLane last, nuint blockCount, uint rowFlags)
	{
		if (blockCount == last.TailBlocks)
		{
			Vector512<uint> lastLane = Vector512.Create(0u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ~0u, ~0u, ~0u, ~0u);
			h0 = Vector512.ConditionalSelect(lastLane, Vector512.Broadcast(Vector128.LoadUnsafe(in key)), h0);
			h1 = Vector512.ConditionalSelect(lastLane, Vector512.Broadcast(Vector128.LoadUnsafe(in key, 4)), h1);
			rowFlags |= Blake3Flags.ChunkStart;
		}

		Vector512<ulong> lengthAndFlags = Vector512.Create((ulong)rowFlags << 32 | (blockCount is 1 ? last.LastLength : BlockLength));
		row3 = Vector512.ConditionalSelect(Vector512.Create(0UL, 0, 0, 0, 0, 0, 0, ~0UL), lengthAndFlags, row3.AsUInt64()).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> CreateRow3(Vector512<ulong> counters, uint flags)
	{
		return Vector512.ConditionalSelect(Vector512.Create(~0UL, 0, ~0UL, 0, ~0UL, 0, ~0UL, 0), counters, Vector512.Create((ulong)flags << 32 | BlockLength)).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadMessage(ref byte block0, ref byte block1, ref byte block2, ref byte block3, out Vector512<uint> m0, out Vector512<uint> m1, out Vector512<uint> m2, out Vector512<uint> m3)
	{
		Prefetch(ref block0);
		Prefetch(ref block1);
		Prefetch(ref block2);
		Prefetch(ref block3);

		Vector512<uint> b0 = Vector512.LoadUnsafe(ref block0).AsUInt32();
		Vector512<uint> b1 = Vector512.LoadUnsafe(ref block1).AsUInt32();
		Vector512<uint> b2 = Vector512.LoadUnsafe(ref block2).AsUInt32();
		Vector512<uint> b3 = Vector512.LoadUnsafe(ref block3).AsUInt32();

		Vector512<uint> t0 = Avx512F.Shuffle4x128(b0, b1, 0b01_00_01_00);
		Vector512<uint> t1 = Avx512F.Shuffle4x128(b0, b1, 0b11_10_11_10);
		Vector512<uint> t2 = Avx512F.Shuffle4x128(b2, b3, 0b01_00_01_00);
		Vector512<uint> t3 = Avx512F.Shuffle4x128(b2, b3, 0b11_10_11_10);

		m0 = Avx512F.Shuffle4x128(t0, t2, 0b10_00_10_00);
		m1 = Avx512F.Shuffle4x128(t0, t2, 0b11_01_11_01);
		m2 = Avx512F.Shuffle4x128(t1, t3, 0b10_00_10_00);
		m3 = Avx512F.Shuffle4x128(t1, t3, 0b11_01_11_01);
	}

	// A prefetch never faults and is only a hint, so its address may lie past the input and needs no pinning: if the input moves meanwhile, the hint is merely wasted.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Prefetch(ref byte block)
	{
		Sse.Prefetch0((byte*)Unsafe.AsPointer(ref block) + PrefetchDistance);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreChainingValues(Vector512<uint> h0, Vector512<uint> h1, nuint count, ref byte output)
	{
		Vector512<ulong> first = Avx512F.PermuteVar8x64x2(h0.AsUInt64(), Vector512.Create(0UL, 1, 8, 9, 2, 3, 10, 11), h1.AsUInt64());
		Vector512<ulong> second = Avx512F.PermuteVar8x64x2(h0.AsUInt64(), Vector512.Create(4UL, 5, 12, 13, 6, 7, 14, 15), h1.AsUInt64());

		if (count is 4)
		{
			first.AsByte().StoreUnsafe(ref output);
			second.AsByte().StoreUnsafe(ref output, 2 * OutLength);
			return;
		}

		if (count is 3)
		{
			first.AsByte().StoreUnsafe(ref output);
		}
		else if (count is 2)
		{
			first.GetLower().AsByte().StoreUnsafe(ref output);
		}

		second.GetUpper().AsByte().StoreUnsafe(ref output, (count - 1) * OutLength);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds(ref Vector512<uint> row0, ref Vector512<uint> row1, ref Vector512<uint> row2, ref Vector512<uint> row3, Vector512<uint> m0, Vector512<uint> m1, Vector512<uint> m2, Vector512<uint> m3)
	{
		Vector512<uint> x0 = Shuffle(m0, m1, 0b10_00_10_00);
		Vector512<uint> y0 = Shuffle(m0, m1, 0b11_01_11_01);
		Vector512<uint> x1 = Avx512F.Shuffle(Shuffle(m2, m3, 0b10_00_10_00), 0b10_01_00_11);
		Vector512<uint> y1 = Avx512F.Shuffle(Shuffle(m2, m3, 0b11_01_11_01), 0b10_01_00_11);
		Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);

		for (int round = 1; round < Blake3Constants.Rounds; ++round)
		{
			PermuteMessage(ref x0, ref y0, ref x1, ref y1);
			Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds
	(
		ref Vector512<uint> row0, ref Vector512<uint> row1, ref Vector512<uint> row2, ref Vector512<uint> row3,
		ref Vector512<uint> row4, ref Vector512<uint> row5, ref Vector512<uint> row6, ref Vector512<uint> row7,
		Vector512<uint> m0, Vector512<uint> m1, Vector512<uint> m2, Vector512<uint> m3,
		Vector512<uint> n0, Vector512<uint> n1, Vector512<uint> n2, Vector512<uint> n3
	)
	{
		Vector512<uint> x0 = Shuffle(m0, m1, 0b10_00_10_00);
		Vector512<uint> y0 = Shuffle(m0, m1, 0b11_01_11_01);
		Vector512<uint> x1 = Avx512F.Shuffle(Shuffle(m2, m3, 0b10_00_10_00), 0b10_01_00_11);
		Vector512<uint> y1 = Avx512F.Shuffle(Shuffle(m2, m3, 0b11_01_11_01), 0b10_01_00_11);
		Vector512<uint> x2 = Shuffle(n0, n1, 0b10_00_10_00);
		Vector512<uint> y2 = Shuffle(n0, n1, 0b11_01_11_01);
		Vector512<uint> x3 = Avx512F.Shuffle(Shuffle(n2, n3, 0b10_00_10_00), 0b10_01_00_11);
		Vector512<uint> y3 = Avx512F.Shuffle(Shuffle(n2, n3, 0b11_01_11_01), 0b10_01_00_11);
		Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);
		Round(ref row4, ref row5, ref row6, ref row7, x2, y2, x3, y3);

		for (int round = 1; round < Blake3Constants.Rounds; ++round)
		{
			PermuteMessage(ref x0, ref y0, ref x1, ref y1);
			PermuteMessage(ref x2, ref y2, ref x3, ref y3);
			Round(ref row0, ref row1, ref row2, ref row3, x0, y0, x1, y1);
			Round(ref row4, ref row5, ref row6, ref row7, x2, y2, x3, y3);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector512<uint> row0, ref Vector512<uint> row1, ref Vector512<uint> row2, ref Vector512<uint> row3, Vector512<uint> x0, Vector512<uint> y0, Vector512<uint> x1, Vector512<uint> y1)
	{
		G(ref row0, ref row1, ref row2, ref row3, x0, y0);

		// Rotating the rows around row1, the last one G writes, keeps the shuffles off its critical path.
		row0 = Avx512F.Shuffle(row0, 0b10_01_00_11);
		row3 = Avx512F.Shuffle(row3, 0b01_00_11_10);
		row2 = Avx512F.Shuffle(row2, 0b00_11_10_01);

		G(ref row0, ref row1, ref row2, ref row3, x1, y1);

		row0 = Avx512F.Shuffle(row0, 0b00_11_10_01);
		row3 = Avx512F.Shuffle(row3, 0b01_00_11_10);
		row2 = Avx512F.Shuffle(row2, 0b10_01_00_11);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector512<uint> row0, ref Vector512<uint> row1, ref Vector512<uint> row2, ref Vector512<uint> row3, Vector512<uint> x, Vector512<uint> y)
	{
		row0 = row0 + x + row1;
		row3 = Avx512F.RotateRight(row3 ^ row0, 16);
		row2 += row3;
		row1 = Avx512F.RotateRight(row1 ^ row2, 12);
		row0 = row0 + y + row1;
		row3 = Avx512F.RotateRight(row3 ^ row0, 8);
		row2 += row3;
		row1 = Avx512F.RotateRight(row1 ^ row2, 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteMessage(ref Vector512<uint> x0, ref Vector512<uint> y0, ref Vector512<uint> x1, ref Vector512<uint> y1)
	{
		Vector512<uint> oddWords = Vector512.Create(0u, ~0u, 0, ~0u, 0, ~0u, 0, ~0u, 0, ~0u, 0, ~0u, 0, ~0u, 0, ~0u);
		Vector512<uint> lastWords = Vector512.Create(0u, 0, 0, ~0u, 0, 0, 0, ~0u, 0, 0, 0, ~0u, 0, 0, 0, ~0u);
		Vector512<uint> nextX0 = Avx512F.Shuffle(Shuffle(x0, y0, 0b11_01_01_10), 0b00_11_10_01);
		Vector512<uint> nextY0 = Vector512.ConditionalSelect(oddWords, Shuffle(x1, y1, 0b11_11_10_10), Avx512F.Shuffle(x0, 0b00_00_11_11));
		Vector512<uint> nextX1 = Avx512F.Shuffle(Vector512.ConditionalSelect(lastWords, x1, Avx512F.UnpackLow(y1.AsUInt64(), y0.AsUInt64()).AsUInt32()), 0b01_11_10_00);
		Vector512<uint> nextY1 = Avx512F.Shuffle(Avx512F.UnpackLow(x1, Avx512F.UnpackHigh(y0, y1)), 0b00_01_11_10);
		x0 = nextX0;
		y0 = nextY0;
		x1 = nextX1;
		y1 = nextY1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> Shuffle(Vector512<uint> left, Vector512<uint> right, [ConstantExpected] byte control)
	{
		return Avx512F.Shuffle(left.AsSingle(), right.AsSingle(), control).AsUInt32();
	}
}
