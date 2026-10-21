using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes up to four inputs with the state of each held as four rows, as Blake3Vector128.Compress does: two inputs to a chain of 256-bit rows, input i of
// a chain in 128-bit lane i. A chain of one input keeps it in lane 1 and rehashes input 0 in lane 0.
// Two inputs make one chain no longer than a single compression; four make two chains, which share the vector ports. Where the 112 vector instructions of
// a round of the four-lane column kernel, not latency, bound it, as on Intel cores, two chains hash four inputs faster.
internal readonly struct Blake3Vector256Rows : IBlake3Kernel
{
	public static bool IsSupported => Avx2.IsSupported;

	// Without the rotations of AVX-512VL the chains grow longer, and on Zen 5, whose vector operations take two cycles, two chains then hash three or four
	// inputs slower than the four-lane kernel.
	private static readonly bool PreferTwoChains = Avx512F.VL.IsSupported || !CpuIdUtils.IsAmdZen5();

	public static int Degree => 4;

	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		if (!PreferTwoChains && length > 2 * ChunkLength)
		{
			Blake3Vector128.HashChunks(ref input, length, in key, counter, flags, ref output);
			return;
		}

		for (; length > 4 * ChunkLength; length -= 4 * ChunkLength)
		{
			Hash4(ref input, 4, 0, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 4 * ChunkLength);
			output = ref Unsafe.Add(ref output, 4 * OutLength);
			counter += 4;
		}

		nuint count = length / ChunkLength;
		nuint tailLength = length % ChunkLength;

		// A partial last chunk takes a lane of its own when a chain has one spare, or when its blocks would take longer on their own than the lane. Where the
		// scalar compressor hashes single chunks faster than a chain, it joins one full chunk from twelve blocks, and two, which then take two chains, always,
		// since the second chain runs in the cycles the first leaves idle; elsewhere it joins one always, and two from ten blocks.
		bool rides = count switch
		{
			0 => false,
			1 => tailLength > (Blake3Compressor.PreferScalar ? 11u : 0u) * BlockLength,
			2 => tailLength > (Blake3Compressor.PreferScalar ? 0u : 9u) * BlockLength,
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
		if (!PreferTwoChains && count > 2)
		{
			Blake3Vector128.HashParents(ref input, count, in key, flags, ref output);
			return;
		}

		for (; count > 4; count -= 4)
		{
			Hash4(ref input, 4, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
			input = ref Unsafe.Add(ref input, 4 * BlockLength);
			output = ref Unsafe.Add(ref output, 4 * OutLength);
		}

		if (count > 2)
		{
			Hash4(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (count is 2)
		{
			Hash2(ref input, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (count is 1)
		{
			Blake3Compressor.Compress(in key, ref input, BlockLength, 0, flags | Blake3Flags.Parent, ref output);
		}
	}

	private static void HashLast(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		if (count > 2)
		{
			Hash4(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else if (count is 2)
		{
			Hash2(ref input, tailLength, in key, counter, flags, ref output);
		}
		else
		{
			Blake3Compressor.HashChunk(ref input, ChunkLength, in key, counter, flags, ref output);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash2(ref byte input, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		bool chunks = (flags & Blake3Flags.Parent) is 0;
		nuint blockCount = chunks ? (nuint)ChunkBlocks : 1;
		nuint stride = blockCount * BlockLength;
		uint startFlags = chunks ? Blake3Flags.ChunkStart : 0;
		uint endFlags = chunks ? Blake3Flags.ChunkEnd : 0;

		Unsafe.SkipInit(out InlineArray64<byte> lastBlock);
		Blake3LastLane last = new(ref Unsafe.Add(ref input, stride), blockCount, tailLength, ref lastBlock);

		Vector256<uint> h0 = Vector256.Create(Vector128.LoadUnsafe(in key));
		Vector256<uint> h1 = Vector256.Create(Vector128.LoadUnsafe(in key, 4));
		Vector256<ulong> counters = Vector256.Create(counter);

		if (chunks)
		{
			counters += Vector256.Create(0UL, 0, 1, 0);
		}

		uint blockFlags = flags | startFlags;

		do
		{
			LoadMessage(ref input, ref last.Next(blockCount), out Vector256<uint> m0, out Vector256<uint> m1, out Vector256<uint> m2, out Vector256<uint> m3);

			uint rowFlags = blockCount is 1 ? blockFlags | endFlags : blockFlags;
			Vector256<uint> row3 = CreateRow3(counters, rowFlags);

			if (blockCount <= last.TailBlocks)
			{
				JoinLastLane(ref h0, ref h1, ref row3, in key, in last, blockCount, rowFlags);
			}

			Vector256<uint> row0 = h0;
			Vector256<uint> row1 = h1;
			Vector256<uint> row2 = Vector256.Create(IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3);

			Rounds(ref row0, ref row1, ref row2, ref row3, m0, m1, m2, m3);

			h0 = row0 ^ row2;
			h1 = row1 ^ row3;
			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		StoreChainingValues(h0, h1, 2, ref output);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash4(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Debug.Assert(count is 3 or 4);

		bool chunks = (flags & Blake3Flags.Parent) is 0;
		nuint blockCount = chunks ? (nuint)ChunkBlocks : 1;
		nuint stride = blockCount * BlockLength;
		uint startFlags = chunks ? Blake3Flags.ChunkStart : 0;
		uint endFlags = chunks ? Blake3Flags.ChunkEnd : 0;

		nuint offset2 = count > 3 ? 2 * stride : 0;
		Unsafe.SkipInit(out InlineArray64<byte> lastBlock);
		Blake3LastLane last = new(ref Unsafe.Add(ref input, (count - 1) * stride), blockCount, tailLength, ref lastBlock);

		Vector256<uint> h0 = Vector256.Create(Vector128.LoadUnsafe(in key));
		Vector256<uint> h1 = Vector256.Create(Vector128.LoadUnsafe(in key, 4));
		Vector256<uint> h2 = h0;
		Vector256<uint> h3 = h1;
		Vector256<ulong> counters0 = Vector256.Create(counter);
		Vector256<ulong> counters1 = counters0;

		if (chunks)
		{
			counters0 += Vector256.Create(0UL, 0, 1, 0);
			counters1 += Vector256.Create(2UL, 0, count - 1, 0);
		}

		uint blockFlags = flags | startFlags;

		do
		{
			LoadMessage(ref input, ref Unsafe.Add(ref input, stride), out Vector256<uint> m0, out Vector256<uint> m1, out Vector256<uint> m2, out Vector256<uint> m3);
			LoadMessage(ref Unsafe.Add(ref input, offset2), ref last.Next(blockCount), out Vector256<uint> n0, out Vector256<uint> n1, out Vector256<uint> n2, out Vector256<uint> n3);

			uint rowFlags = blockCount is 1 ? blockFlags | endFlags : blockFlags;
			Vector256<uint> row3 = CreateRow3(counters0, rowFlags);
			Vector256<uint> row7 = CreateRow3(counters1, rowFlags);

			if (blockCount <= last.TailBlocks)
			{
				JoinLastLane(ref h2, ref h3, ref row7, in key, in last, blockCount, rowFlags);
			}

			Vector256<uint> row0 = h0;
			Vector256<uint> row1 = h1;
			Vector256<uint> row2 = Vector256.Create(IV0, IV1, IV2, IV3, IV0, IV1, IV2, IV3);
			Vector256<uint> row4 = h2;
			Vector256<uint> row5 = h3;
			Vector256<uint> row6 = row2;

			Rounds(ref row0, ref row1, ref row2, ref row3, ref row4, ref row5, ref row6, ref row7, m0, m1, m2, m3, n0, n1, n2, n3);

			h0 = row0 ^ row2;
			h1 = row1 ^ row3;
			h2 = row4 ^ row6;
			h3 = row5 ^ row7;
			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		StoreChainingValues(h0, h1, 2, ref output);
		StoreChainingValues(h2, h3, count - 2, ref Unsafe.Add(ref output, 2 * OutLength));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void JoinLastLane(ref Vector256<uint> h0, ref Vector256<uint> h1, ref Vector256<uint> row3, ref readonly uint key, ref readonly Blake3LastLane last, nuint blockCount, uint rowFlags)
	{
		if (blockCount == last.TailBlocks)
		{
			h0 = Avx2.Blend(h0, Vector256.Create(Vector128.LoadUnsafe(in key)), 0b1111_0000);
			h1 = Avx2.Blend(h1, Vector256.Create(Vector128.LoadUnsafe(in key, 4)), 0b1111_0000);
			rowFlags |= Blake3Flags.ChunkStart;
		}

		Vector256<ulong> lengthAndFlags = Vector256.Create((ulong)rowFlags << 32 | (blockCount is 1 ? last.LastLength : BlockLength));
		row3 = Avx2.Blend(row3, lengthAndFlags.AsUInt32(), 0b1100_0000);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> CreateRow3(Vector256<ulong> counters, uint flags)
	{
		return Avx2.Blend(counters.AsUInt32(), Vector256.Create((ulong)flags << 32 | BlockLength).AsUInt32(), 0b1100_1100);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadMessage(ref byte block0, ref byte block1, out Vector256<uint> m0, out Vector256<uint> m1, out Vector256<uint> m2, out Vector256<uint> m3)
	{
		m0 = Vector256.Create(Vector128.LoadUnsafe(ref block0), Vector128.LoadUnsafe(ref block1)).AsUInt32();
		m1 = Vector256.Create(Vector128.LoadUnsafe(ref block0, 16), Vector128.LoadUnsafe(ref block1, 16)).AsUInt32();
		m2 = Vector256.Create(Vector128.LoadUnsafe(ref block0, 32), Vector128.LoadUnsafe(ref block1, 32)).AsUInt32();
		m3 = Vector256.Create(Vector128.LoadUnsafe(ref block0, 48), Vector128.LoadUnsafe(ref block1, 48)).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreChainingValues(Vector256<uint> h0, Vector256<uint> h1, nuint count, ref byte output)
	{
		Vector256<uint> upper = Vector256.ConcatUpper(h0, h1);

		if (count is 2)
		{
			Vector256.ConcatLower(h0, h1).AsByte().StoreUnsafe(ref output);
			output = ref Unsafe.Add(ref output, OutLength);
		}

		upper.AsByte().StoreUnsafe(ref output);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds(ref Vector256<uint> row0, ref Vector256<uint> row1, ref Vector256<uint> row2, ref Vector256<uint> row3, Vector256<uint> m0, Vector256<uint> m1, Vector256<uint> m2, Vector256<uint> m3)
	{
		Vector256<uint> x0 = Shuffle(m0, m1, 0b10_00_10_00);
		Vector256<uint> y0 = Shuffle(m0, m1, 0b11_01_11_01);
		Vector256<uint> x1 = Avx2.Shuffle(Shuffle(m2, m3, 0b10_00_10_00), 0b10_01_00_11);
		Vector256<uint> y1 = Avx2.Shuffle(Shuffle(m2, m3, 0b11_01_11_01), 0b10_01_00_11);
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
		ref Vector256<uint> row0, ref Vector256<uint> row1, ref Vector256<uint> row2, ref Vector256<uint> row3,
		ref Vector256<uint> row4, ref Vector256<uint> row5, ref Vector256<uint> row6, ref Vector256<uint> row7,
		Vector256<uint> m0, Vector256<uint> m1, Vector256<uint> m2, Vector256<uint> m3,
		Vector256<uint> n0, Vector256<uint> n1, Vector256<uint> n2, Vector256<uint> n3
	)
	{
		Vector256<uint> x0 = Shuffle(m0, m1, 0b10_00_10_00);
		Vector256<uint> y0 = Shuffle(m0, m1, 0b11_01_11_01);
		Vector256<uint> x1 = Avx2.Shuffle(Shuffle(m2, m3, 0b10_00_10_00), 0b10_01_00_11);
		Vector256<uint> y1 = Avx2.Shuffle(Shuffle(m2, m3, 0b11_01_11_01), 0b10_01_00_11);
		Vector256<uint> x2 = Shuffle(n0, n1, 0b10_00_10_00);
		Vector256<uint> y2 = Shuffle(n0, n1, 0b11_01_11_01);
		Vector256<uint> x3 = Avx2.Shuffle(Shuffle(n2, n3, 0b10_00_10_00), 0b10_01_00_11);
		Vector256<uint> y3 = Avx2.Shuffle(Shuffle(n2, n3, 0b11_01_11_01), 0b10_01_00_11);
		Round(ref row0, ref row1, ref row2, ref row3, ref row4, ref row5, ref row6, ref row7, x0, y0, x1, y1, x2, y2, x3, y3);

		for (int round = 1; round < Blake3Constants.Rounds; ++round)
		{
			PermuteMessage(ref x0, ref y0, ref x1, ref y1);
			PermuteMessage(ref x2, ref y2, ref x3, ref y3);
			Round(ref row0, ref row1, ref row2, ref row3, ref row4, ref row5, ref row6, ref row7, x0, y0, x1, y1, x2, y2, x3, y3);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector256<uint> row0, ref Vector256<uint> row1, ref Vector256<uint> row2, ref Vector256<uint> row3, Vector256<uint> x0, Vector256<uint> y0, Vector256<uint> x1, Vector256<uint> y1)
	{
		G(ref row0, ref row1, ref row2, ref row3, x0, y0);
		Diagonalize(ref row0, ref row2, ref row3);
		G(ref row0, ref row1, ref row2, ref row3, x1, y1);
		Undiagonalize(ref row0, ref row2, ref row3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round
	(
		ref Vector256<uint> a0, ref Vector256<uint> a1, ref Vector256<uint> a2, ref Vector256<uint> a3,
		ref Vector256<uint> b0, ref Vector256<uint> b1, ref Vector256<uint> b2, ref Vector256<uint> b3,
		Vector256<uint> xa0, Vector256<uint> ya0, Vector256<uint> xa1, Vector256<uint> ya1,
		Vector256<uint> xb0, Vector256<uint> yb0, Vector256<uint> xb1, Vector256<uint> yb1
	)
	{
		G(ref a0, ref a1, ref a2, ref a3, xa0, ya0);
		G(ref b0, ref b1, ref b2, ref b3, xb0, yb0);
		Diagonalize(ref a0, ref a2, ref a3);
		Diagonalize(ref b0, ref b2, ref b3);
		G(ref a0, ref a1, ref a2, ref a3, xa1, ya1);
		G(ref b0, ref b1, ref b2, ref b3, xb1, yb1);
		Undiagonalize(ref a0, ref a2, ref a3);
		Undiagonalize(ref b0, ref b2, ref b3);
	}

	// Rotating the rows around row1, the last one G writes, keeps the shuffles off its critical path.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Diagonalize(ref Vector256<uint> row0, ref Vector256<uint> row2, ref Vector256<uint> row3)
	{
		row0 = Avx2.Shuffle(row0, 0b10_01_00_11);
		row3 = Avx2.Shuffle(row3, 0b01_00_11_10);
		row2 = Avx2.Shuffle(row2, 0b00_11_10_01);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Undiagonalize(ref Vector256<uint> row0, ref Vector256<uint> row2, ref Vector256<uint> row3)
	{
		row0 = Avx2.Shuffle(row0, 0b00_11_10_01);
		row3 = Avx2.Shuffle(row3, 0b01_00_11_10);
		row2 = Avx2.Shuffle(row2, 0b10_01_00_11);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector256<uint> row0, ref Vector256<uint> row1, ref Vector256<uint> row2, ref Vector256<uint> row3, Vector256<uint> x, Vector256<uint> y)
	{
		row0 = row0 + x + row1;
		row3 = (row3 ^ row0).RotateRightUInt32(16);
		row2 += row3;
		row1 = (row1 ^ row2).RotateRightUInt32(12);
		row0 = row0 + y + row1;
		row3 = (row3 ^ row0).RotateRightUInt32(8);
		row2 += row3;
		row1 = (row1 ^ row2).RotateRightUInt32(7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PermuteMessage(ref Vector256<uint> x0, ref Vector256<uint> y0, ref Vector256<uint> x1, ref Vector256<uint> y1)
	{
		Vector256<uint> nextX0 = Avx2.Shuffle(Shuffle(x0, y0, 0b11_01_01_10), 0b00_11_10_01);
		Vector256<uint> nextY0 = Avx2.Blend(Avx2.Shuffle(x0, 0b00_00_11_11), Shuffle(x1, y1, 0b11_11_10_10), 0b1010_1010);
		Vector256<uint> nextX1 = Avx2.Shuffle(Avx2.Blend(Avx2.UnpackLow(y1.AsUInt64(), y0.AsUInt64()).AsUInt32(), x1, 0b1000_1000), 0b01_11_10_00);
		Vector256<uint> nextY1 = Avx2.Shuffle(Avx2.UnpackLow(x1, Avx2.UnpackHigh(y0, y1)), 0b00_01_11_10);
		x0 = nextX0;
		y0 = nextY0;
		x1 = nextX1;
		y1 = nextY1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> Shuffle(Vector256<uint> left, Vector256<uint> right, [ConstantExpected] byte control)
	{
		return Avx.Shuffle(left.AsSingle(), right.AsSingle(), control).AsUInt32();
	}
}
