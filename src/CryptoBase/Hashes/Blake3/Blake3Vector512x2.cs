using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes 32 consecutive full chunks as two groups of 16, each laid out as in Blake3Vector512, with the steps of the two groups interleaved half by half:
// where vector additions and rotations take two cycles, as on Zen 5, one group alone leaves the vector pipelines waiting on the latency of each G, and the
// other group fills those cycles. Fewer chunks, and all parents, take Blake3Vector512.
internal readonly struct Blake3Vector512x2 : IBlake3Kernel
{
	public static bool IsSupported => Blake3Vector512.IsSupported;

	// Measured faster than Blake3Vector512 on Zen 5 only. A thread whose core it shares with another hashing thread measured about as fast, and at most 5%
	// slower, with either kernel, so threads take it whether or not they share cores. Cores that split 512-bit operations are bound by their throughput,
	// with no cycles for the second group to fill.
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

	// The two states take all 32 vector registers, so the steps read the message words from memory; locals of this frame measured faster for them than a
	// buffer from stackalloc or the heap.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash(ref byte input, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		ref uint k = ref Unsafe.AsRef(in key);
		Vector512<uint> h0 = Vector512.Create(k);
		Vector512<uint> h1 = Vector512.Create(Unsafe.Add(ref k, 1));
		Vector512<uint> h2 = Vector512.Create(Unsafe.Add(ref k, 2));
		Vector512<uint> h3 = Vector512.Create(Unsafe.Add(ref k, 3));
		Vector512<uint> h4 = Vector512.Create(Unsafe.Add(ref k, 4));
		Vector512<uint> h5 = Vector512.Create(Unsafe.Add(ref k, 5));
		Vector512<uint> h6 = Vector512.Create(Unsafe.Add(ref k, 6));
		Vector512<uint> h7 = Vector512.Create(Unsafe.Add(ref k, 7));
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

		do
		{
			// Near the end of the chunks, prefetch the next batch, which follows in memory; a mask measured faster than a conditional.
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

			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 0, 2, 4, 6);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 0, 2, 4, 6);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 1, 3, 5, 7);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 1, 3, 5, 7);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 8, 10, 12, 14);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 8, 10, 12, 14);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 9, 11, 13, 15);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 9, 11, 13, 15);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 2, 3, 7, 4);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 2, 3, 7, 4);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 6, 10, 0, 13);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 6, 10, 0, 13);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 1, 12, 9, 15);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 1, 12, 9, 15);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 11, 5, 14, 8);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 11, 5, 14, 8);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 3, 10, 13, 7);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 3, 10, 13, 7);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 4, 12, 2, 14);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 4, 12, 2, 14);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 6, 9, 11, 8);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 6, 9, 11, 8);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 5, 0, 15, 1);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 5, 0, 15, 1);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 10, 12, 14, 13);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 10, 12, 14, 13);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 7, 9, 3, 15);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 7, 9, 3, 15);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 4, 11, 5, 1);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 4, 11, 5, 1);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 0, 2, 8, 6);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 0, 2, 8, 6);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 12, 9, 15, 14);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 12, 9, 15, 14);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 13, 11, 10, 8);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 13, 11, 10, 8);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 7, 5, 0, 6);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 7, 5, 0, 6);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 2, 3, 1, 4);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 2, 3, 1, 4);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 9, 11, 8, 15);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 9, 11, 8, 15);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 14, 5, 12, 1);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 14, 5, 12, 1);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 13, 0, 2, 4);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 13, 0, 2, 4);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 3, 10, 6, 7);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 3, 10, 6, 7);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 11, 5, 1, 8);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 11, 5, 1, 8);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message0[0], 15, 0, 9, 6);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref message1[0], 15, 0, 9, 6);
			HalfX(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 14, 2, 3, 7);
			HalfX(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 14, 2, 3, 7);
			HalfY(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message0[0], 10, 12, 4, 13);
			HalfY(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref message1[0], 10, 12, 4, 13);

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

	// Each half holds its rotation counts as literal constants; otherwise the JIT rotated by vectors of counts, which took registers that the two states need.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void HalfX
	(
		ref Vector512<uint> a0, ref Vector512<uint> a1, ref Vector512<uint> a2, ref Vector512<uint> a3,
		ref Vector512<uint> b0, ref Vector512<uint> b1, ref Vector512<uint> b2, ref Vector512<uint> b3,
		ref Vector512<uint> c0, ref Vector512<uint> c1, ref Vector512<uint> c2, ref Vector512<uint> c3,
		ref Vector512<uint> d0, ref Vector512<uint> d1, ref Vector512<uint> d2, ref Vector512<uint> d3,
		ref Vector512<uint> message,
		int x0, int x1, int x2, int x3
	)
	{
		a0 = a0 + Unsafe.Add(ref message, x0) + b0;
		a1 = a1 + Unsafe.Add(ref message, x1) + b1;
		a2 = a2 + Unsafe.Add(ref message, x2) + b2;
		a3 = a3 + Unsafe.Add(ref message, x3) + b3;
		d0 = Avx512F.RotateRight(d0 ^ a0, 16);
		d1 = Avx512F.RotateRight(d1 ^ a1, 16);
		d2 = Avx512F.RotateRight(d2 ^ a2, 16);
		d3 = Avx512F.RotateRight(d3 ^ a3, 16);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = Avx512F.RotateRight(b0 ^ c0, 12);
		b1 = Avx512F.RotateRight(b1 ^ c1, 12);
		b2 = Avx512F.RotateRight(b2 ^ c2, 12);
		b3 = Avx512F.RotateRight(b3 ^ c3, 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void HalfY
	(
		ref Vector512<uint> a0, ref Vector512<uint> a1, ref Vector512<uint> a2, ref Vector512<uint> a3,
		ref Vector512<uint> b0, ref Vector512<uint> b1, ref Vector512<uint> b2, ref Vector512<uint> b3,
		ref Vector512<uint> c0, ref Vector512<uint> c1, ref Vector512<uint> c2, ref Vector512<uint> c3,
		ref Vector512<uint> d0, ref Vector512<uint> d1, ref Vector512<uint> d2, ref Vector512<uint> d3,
		ref Vector512<uint> message,
		int x0, int x1, int x2, int x3
	)
	{
		a0 = a0 + Unsafe.Add(ref message, x0) + b0;
		a1 = a1 + Unsafe.Add(ref message, x1) + b1;
		a2 = a2 + Unsafe.Add(ref message, x2) + b2;
		a3 = a3 + Unsafe.Add(ref message, x3) + b3;
		d0 = Avx512F.RotateRight(d0 ^ a0, 8);
		d1 = Avx512F.RotateRight(d1 ^ a1, 8);
		d2 = Avx512F.RotateRight(d2 ^ a2, 8);
		d3 = Avx512F.RotateRight(d3 ^ a3, 8);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = Avx512F.RotateRight(b0 ^ c0, 7);
		b1 = Avx512F.RotateRight(b1 ^ c1, 7);
		b2 = Avx512F.RotateRight(b2 ^ c2, 7);
		b3 = Avx512F.RotateRight(b3 ^ c3, 7);
	}
}
