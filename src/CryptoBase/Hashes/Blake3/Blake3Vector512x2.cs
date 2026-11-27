using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes 32 consecutive full chunks as two groups of 16, each laid out as in Blake3Vector512, with the steps of the two groups interleaved half by half.
// Where vector additions and rotations take two cycles, as on Zen 5, one group alone leaves the vector pipelines waiting on the latency of each G, and the other group fills those cycles.
// Fewer chunks, and all parents, take Blake3Vector512.
internal readonly struct Blake3Vector512x2 : IBlake3Kernel
{
	public static bool IsSupported => Blake3Vector512.IsSupported;

	// Only Zen 5 with a 512-bit datapath leaves cycles for the second group to fill; cores that split 512-bit operations are bound by their throughput.
	// Threads take it whether or not they share a core.
	internal static readonly bool IsPreferred = IsSupported && CpuIdUtils.IsAmdZen5With512BitDatapath();

	public static int Degree => 32;

	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length >= 32 * ChunkLength; length -= 32 * ChunkLength)
		{
			Hash(ref input, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 32 * ChunkLength);
			output = ref Unsafe.Add(ref output, 32 * OutLength);
			counter += 32;
		}

		if (length is not 0)
		{
			Blake3Vector512.HashChunks(ref input, length, in key, counter, flags, ref output);
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		Blake3Vector512.HashParents(ref input, count, in key, flags, ref output);
	}

	// The two states take all 32 vector registers, so the steps read the message words from memory, through MessageByteOffsets512, kept in locals of this frame rather than in a buffer from stackalloc or the heap.
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash(ref byte input, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		Blake3Vector512.BroadcastKey(in key, out Vector512<uint> h0, out Vector512<uint> h1, out Vector512<uint> h2, out Vector512<uint> h3, out Vector512<uint> h4, out Vector512<uint> h5, out Vector512<uint> h6, out Vector512<uint> h7);
		Vector512<uint> g0 = h0;
		Vector512<uint> g1 = h1;
		Vector512<uint> g2 = h2;
		Vector512<uint> g3 = h3;
		Vector512<uint> g4 = h4;
		Vector512<uint> g5 = h5;
		Vector512<uint> g6 = h6;
		Vector512<uint> g7 = h7;
		Vector512<uint> counterLow0 = Vector512.Create((uint)counter) + Vector512<uint>.Indices;
		Vector512<uint> counterLow1 = counterLow0 + Vector512.Create(16u);
		Vector512<uint> counterHigh0 = Vector512.Create((uint)(counter >> 32)) - Vector512.LessThan(counterLow0, Vector512.Create((uint)counter));
		Vector512<uint> counterHigh1 = Vector512.Create((uint)(counter >> 32)) - Vector512.LessThan(counterLow1, Vector512.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> message0);
		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> message1);
		uint blockFlags = flags | Blake3Flags.ChunkStart;
		nuint blockCount = ChunkBlocks;
		ref ushort schedule = ref MemoryMarshal.GetReference(MessageByteOffsets512);

		do
		{
			// Near the end of the chunks, prefetch the next batch, which follows in memory; the offset is masked rather than chosen by a conditional.
			const nuint nextBatch = 31 * ChunkLength;
			nuint skip = (nuint)((nint)(blockCount - PrefetchDistance / BlockLength - 1) >> 8 * nint.Size - 1) & nextBatch;
			Blake3Vector512.PrefetchFull(ref input, skip);
			Blake3Vector512.PrefetchFull(ref Unsafe.Add(ref input, 16 * ChunkLength), skip);
			Blake3Vector512.LoadMessageFull(ref input, ref message0[0]);
			Blake3Vector512.LoadMessageFull(ref Unsafe.Add(ref input, 16 * ChunkLength), ref message1[0]);
			Vector512<uint> laneFlags = Vector512.Create(blockCount is 1 ? blockFlags | Blake3Flags.ChunkEnd : blockFlags);

			Vector512<uint> v0 = h0;
			Vector512<uint> v1 = h1;
			Vector512<uint> v2 = h2;
			Vector512<uint> v3 = h3;
			Vector512<uint> v4 = h4;
			Vector512<uint> v5 = h5;
			Vector512<uint> v6 = h6;
			Vector512<uint> v7 = h7;
			Vector512<uint> v8 = Vector512.Create(IV0);
			Vector512<uint> v9 = Vector512.Create(IV1);
			Vector512<uint> v10 = Vector512.Create(IV2);
			Vector512<uint> v11 = Vector512.Create(IV3);
			Vector512<uint> v12 = counterLow0;
			Vector512<uint> v13 = counterHigh0;
			Vector512<uint> v14 = Vector512.Create((uint)BlockLength);
			Vector512<uint> v15 = laneFlags;
			Vector512<uint> w0 = g0;
			Vector512<uint> w1 = g1;
			Vector512<uint> w2 = g2;
			Vector512<uint> w3 = g3;
			Vector512<uint> w4 = g4;
			Vector512<uint> w5 = g5;
			Vector512<uint> w6 = g6;
			Vector512<uint> w7 = g7;
			Vector512<uint> w8 = Vector512.Create(IV0);
			Vector512<uint> w9 = Vector512.Create(IV1);
			Vector512<uint> w10 = Vector512.Create(IV2);
			Vector512<uint> w11 = Vector512.Create(IV3);
			Vector512<uint> w12 = counterLow1;
			Vector512<uint> w13 = counterHigh1;
			Vector512<uint> w14 = Vector512.Create((uint)BlockLength);
			Vector512<uint> w15 = laneFlags;

			// A loop of rounds, as in Blake3Vector512, keeps the hot code under 4 KB.
			for (int round = 0; round < Rounds; ++round)
			{
				ref ushort words = ref Unsafe.Add(ref schedule, round * 16);
				Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], ref words, 0, 16, 12);
				Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], ref words, 0, 16, 12);
				Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], ref words, 4, 8, 7);
				Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], ref words, 4, 8, 7);
				Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], ref words, 8, 16, 12);
				Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], ref words, 8, 16, 12);
				Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], ref words, 12, 8, 7);
				Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], ref words, 12, 8, 7);
			}

			h0 = v0 ^ v8;
			h1 = v1 ^ v9;
			h2 = v2 ^ v10;
			h3 = v3 ^ v11;
			h4 = v4 ^ v12;
			h5 = v5 ^ v13;
			h6 = v6 ^ v14;
			h7 = v7 ^ v15;
			g0 = w0 ^ w8;
			g1 = w1 ^ w9;
			g2 = w2 ^ w10;
			g3 = w3 ^ w11;
			g4 = w4 ^ w12;
			g5 = w5 ^ w13;
			g6 = w6 ^ w14;
			g7 = w7 ^ w15;

			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		Blake3Vector512.StoreChainingValues(h0, h1, h2, h3, h4, h5, h6, h7, ref output);
		Blake3Vector512.StoreChainingValues(g0, g1, g2, g3, g4, g5, g6, g7, ref Unsafe.Add(ref output, 16 * OutLength));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<uint> Word(ref Vector512<uint> message, ref ushort words, int i)
	{
		return Unsafe.AddByteOffset(ref message, (nuint)Unsafe.Add(ref words, i));
	}

	// Half of G on four columns or four diagonals of one state.
	// The rotation counts are constants, so that each rotation is a single instruction with an immediate.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Half
	(
		ref Vector512<uint> a0, ref Vector512<uint> a1, ref Vector512<uint> a2, ref Vector512<uint> a3,
		ref Vector512<uint> b0, ref Vector512<uint> b1, ref Vector512<uint> b2, ref Vector512<uint> b3,
		ref Vector512<uint> c0, ref Vector512<uint> c1, ref Vector512<uint> c2, ref Vector512<uint> c3,
		ref Vector512<uint> d0, ref Vector512<uint> d1, ref Vector512<uint> d2, ref Vector512<uint> d3,
		ref Vector512<uint> message,
		ref ushort words, int first,
		[ConstantExpected] byte rotationD, [ConstantExpected] byte rotationB
	)
	{
		a0 = a0 + Word(ref message, ref words, first + 0) + b0;
		a1 = a1 + Word(ref message, ref words, first + 1) + b1;
		a2 = a2 + Word(ref message, ref words, first + 2) + b2;
		a3 = a3 + Word(ref message, ref words, first + 3) + b3;
		d0 = Avx512F.RotateRight(d0 ^ a0, rotationD);
		d1 = Avx512F.RotateRight(d1 ^ a1, rotationD);
		d2 = Avx512F.RotateRight(d2 ^ a2, rotationD);
		d3 = Avx512F.RotateRight(d3 ^ a3, rotationD);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = Avx512F.RotateRight(b0 ^ c0, rotationB);
		b1 = Avx512F.RotateRight(b1 ^ c1, rotationB);
		b2 = Avx512F.RotateRight(b2 ^ c2, rotationB);
		b3 = Avx512F.RotateRight(b3 ^ c3, rotationB);
	}
}
