using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

// Hashes eight inputs as two groups of four, each laid out as in Blake3Vector128, with the steps of the two groups interleaved half by half: one group
// alone leaves the vector pipelines of Apple cores waiting on the latency of each G, and the other group fills those cycles.
internal readonly struct Blake3Vector128x2 : IBlake3Kernel
{
	public static bool IsSupported => AdvSimd.Arm64.IsSupported;

	// Measured faster than the four-lane kernel on Apple M2; other cores may have fewer vector pipelines, and no cycles to spare for the second group.
	internal static readonly bool IsPreferred = IsSupported && (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS() || OperatingSystem.IsTvOS());

	public static int Degree => 8;

	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length > 8 * ChunkLength; length -= 8 * ChunkLength)
		{
			Hash(ref input, 8, 0, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 8 * ChunkLength);
			output = ref Unsafe.Add(ref output, 8 * OutLength);
			counter += 8;
		}

		nuint count = length / ChunkLength;
		nuint tailLength = length % ChunkLength;

		// Five inputs or more, a partial chunk after them taking one more lane, hash faster in the two groups than in lanes of four and on their own.
		if (count > 4)
		{
			HashLast(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else
		{
			Blake3Vector128.HashChunks(ref input, length, in key, counter, flags, ref output);
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		for (; count >= 8; count -= 8)
		{
			Hash(ref input, 8, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
			input = ref Unsafe.Add(ref input, 8 * BlockLength);
			output = ref Unsafe.Add(ref output, 8 * OutLength);
		}

		if (count > 4)
		{
			Hash(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else
		{
			Blake3Vector128.HashParents(ref input, count, in key, flags, ref output);
		}
	}

	private static void HashLast(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		nuint tailBlocks = tailLength is 0 ? 0 : (tailLength - 1) / BlockLength;
		Hash(ref input, tailBlocks is 0 ? count : count + 1, tailBlocks, in key, counter, flags, ref output);

		if (tailLength is not 0)
		{
			Blake3Compressor.FinishChunk(ref Unsafe.Add(ref input, count * ChunkLength), tailLength, in key, counter + count, flags, ref Unsafe.Add(ref output, count * OutLength));
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Hash(ref byte input, nuint count, nuint tailBlocks, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		bool chunks = (flags & Blake3Flags.Parent) is 0;
		nuint blockCount = chunks ? (nuint)ChunkBlocks : 1;
		nuint stride = blockCount * BlockLength;
		uint startFlags = chunks ? Blake3Flags.ChunkStart : 0;
		uint endFlags = chunks ? Blake3Flags.ChunkEnd : 0;

		Debug.Assert(count is > 4 and <= 8);
		Debug.Assert(tailBlocks < blockCount);
		Debug.Assert(tailBlocks is 0 || count > 5);

		// Lanes past count rehash the last input, which keeps every load inside the input; the second group loads relative to input 4.
		nuint offset1 = stride;
		nuint offset2 = 2 * stride;
		nuint offset3 = 3 * stride;
		nuint offset4 = 4 * stride;
		nuint lastOffset = (count - 1) * stride - (tailBlocks is 0 ? 0 : (blockCount - tailBlocks) * BlockLength) - offset4;
		nuint offset5 = count > 6 ? stride : lastOffset;
		nuint offset6 = count > 7 ? 2 * stride : lastOffset;
		nuint offset7 = lastOffset;

		ref uint k = ref Unsafe.AsRef(in key);
		Vector128<uint> h0 = Vector128.Create(k);
		Vector128<uint> h1 = Vector128.Create(Unsafe.Add(ref k, 1));
		Vector128<uint> h2 = Vector128.Create(Unsafe.Add(ref k, 2));
		Vector128<uint> h3 = Vector128.Create(Unsafe.Add(ref k, 3));
		Vector128<uint> h4 = Vector128.Create(Unsafe.Add(ref k, 4));
		Vector128<uint> h5 = Vector128.Create(Unsafe.Add(ref k, 5));
		Vector128<uint> h6 = Vector128.Create(Unsafe.Add(ref k, 6));
		Vector128<uint> h7 = Vector128.Create(Unsafe.Add(ref k, 7));
		Vector128<uint> g0 = h0;
		Vector128<uint> g1 = h1;
		Vector128<uint> g2 = h2;
		Vector128<uint> g3 = h3;
		Vector128<uint> g4 = h4;
		Vector128<uint> g5 = h5;
		Vector128<uint> g6 = h6;
		Vector128<uint> g7 = h7;
		Vector128<uint> counterLow0 = Vector128.Create((uint)counter);
		Vector128<uint> counterLow1 = counterLow0;

		if (chunks)
		{
			counterLow0 += Vector128<uint>.Indices;
			counterLow1 += Vector128<uint>.Indices + Vector128.Create(4u);
		}

		Vector128<uint> counterHigh0 = Vector128.Create((uint)(counter >> 32)) - Vector128.LessThan(counterLow0, Vector128.Create((uint)counter));
		Vector128<uint> counterHigh1 = Vector128.Create((uint)(counter >> 32)) - Vector128.LessThan(counterLow1, Vector128.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector128<uint>> message0);
		Unsafe.SkipInit(out InlineArray16<Vector128<uint>> message1);
		uint blockFlags = flags | startFlags;
		Unsafe.SkipInit(out Vector128<uint> t);

		do
		{
			Blake3Vector128.LoadMessage(ref input, offset1, offset2, offset3, ref message0[0]);
			Blake3Vector128.LoadMessage(ref Unsafe.Add(ref input, offset4), offset5, offset6, offset7, ref message1[0]);
			Vector128<uint> laneFlags0 = Vector128.Create(blockCount is 1 ? blockFlags | endFlags : blockFlags);
			Vector128<uint> laneFlags1 = laneFlags0;

			if (blockCount <= tailBlocks)
			{
				Vector128<uint> tail = Vector128.GreaterThanOrEqual(Vector128<uint>.Indices, Vector128.Create((uint)count - 5));
				uint tailFlags = flags;

				if (blockCount == tailBlocks)
				{
					g0 = Vector128.ConditionalSelect(tail, Vector128.Create(k), g0);
					g1 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 1)), g1);
					g2 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 2)), g2);
					g3 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 3)), g3);
					g4 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 4)), g4);
					g5 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 5)), g5);
					g6 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 6)), g6);
					g7 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 7)), g7);
					tailFlags |= startFlags;
				}

				laneFlags1 = Vector128.ConditionalSelect(tail, Vector128.Create(tailFlags), laneFlags1);
			}

			Vector128<uint> v0 = h0;
			Vector128<uint> v1 = h1;
			Vector128<uint> v2 = h2;
			Vector128<uint> v3 = h3;
			Vector128<uint> v4 = h4;
			Vector128<uint> v5 = h5;
			Vector128<uint> v6 = h6;
			Vector128<uint> v7 = h7;
			Vector128<uint> v8 = Vector128.Create(IV0);
			Vector128<uint> v9 = Vector128.Create(IV1);
			Vector128<uint> v10 = Vector128.Create(IV2);
			Vector128<uint> v11 = Vector128.Create(IV3);
			Vector128<uint> v12 = counterLow0;
			Vector128<uint> v13 = counterHigh0;
			Vector128<uint> v14 = Vector128.Create((uint)BlockLength);
			Vector128<uint> v15 = laneFlags0;
			Vector128<uint> w0 = g0;
			Vector128<uint> w1 = g1;
			Vector128<uint> w2 = g2;
			Vector128<uint> w3 = g3;
			Vector128<uint> w4 = g4;
			Vector128<uint> w5 = g5;
			Vector128<uint> w6 = g6;
			Vector128<uint> w7 = g7;
			Vector128<uint> w8 = Vector128.Create(IV0);
			Vector128<uint> w9 = Vector128.Create(IV1);
			Vector128<uint> w10 = Vector128.Create(IV2);
			Vector128<uint> w11 = Vector128.Create(IV3);
			Vector128<uint> w12 = counterLow1;
			Vector128<uint> w13 = counterHigh1;
			Vector128<uint> w14 = Vector128.Create((uint)BlockLength);
			Vector128<uint> w15 = laneFlags1;

			// The steps of Blake3Vector128.RoundsAvx512Vl, each running its first half on both groups, then its second half on both. Interleaving whole steps
			// instead keeps too little independent work within reach of the core, and was slower than one group of four lanes.
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 0, 2, 4, 6, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 0, 2, 4, 6, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 1, 3, 5, 7, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 1, 3, 5, 7, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 8, 10, 12, 14, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 8, 10, 12, 14, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 9, 11, 13, 15, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 9, 11, 13, 15, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 2, 3, 7, 4, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 2, 3, 7, 4, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 6, 10, 0, 13, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 6, 10, 0, 13, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 1, 12, 9, 15, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 1, 12, 9, 15, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 11, 5, 14, 8, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 11, 5, 14, 8, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 3, 10, 13, 7, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 3, 10, 13, 7, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 4, 12, 2, 14, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 4, 12, 2, 14, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 6, 9, 11, 8, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 6, 9, 11, 8, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 5, 0, 15, 1, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 5, 0, 15, 1, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 10, 12, 14, 13, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 10, 12, 14, 13, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 7, 9, 3, 15, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 7, 9, 3, 15, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 4, 11, 5, 1, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 4, 11, 5, 1, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 0, 2, 8, 6, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 0, 2, 8, 6, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 12, 9, 15, 14, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 12, 9, 15, 14, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 13, 11, 10, 8, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 13, 11, 10, 8, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 7, 5, 0, 6, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 7, 5, 0, 6, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 2, 3, 1, 4, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 2, 3, 1, 4, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 9, 11, 8, 15, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 9, 11, 8, 15, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 14, 5, 12, 1, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 14, 5, 12, 1, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 13, 0, 2, 4, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 13, 0, 2, 4, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 3, 10, 6, 7, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 3, 10, 6, 7, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 11, 5, 1, 8, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 11, 5, 1, 8, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref t, ref message0[0], 15, 0, 9, 6, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w4, ref w5, ref w6, ref w7, ref w8, ref w9, ref w10, ref w11, ref w12, ref w13, ref w14, ref w15, ref t, ref message1[0], 15, 0, 9, 6, false);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 14, 2, 3, 7, true);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 14, 2, 3, 7, true);
			Half(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref t, ref message0[0], 10, 12, 4, 13, false);
			Half(ref w0, ref w1, ref w2, ref w3, ref w5, ref w6, ref w7, ref w4, ref w10, ref w11, ref w8, ref w9, ref w15, ref w12, ref w13, ref w14, ref t, ref message1[0], 10, 12, 4, 13, false);

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

		VectorTranspose.Transpose(ref h0, ref h1, ref h2, ref h3);
		VectorTranspose.Transpose(ref h4, ref h5, ref h6, ref h7);
		VectorTranspose.Transpose(ref g0, ref g1, ref g2, ref g3);
		VectorTranspose.Transpose(ref g4, ref g5, ref g6, ref g7);

		h0.AsByte().StoreUnsafe(ref output);
		h4.AsByte().StoreUnsafe(ref output, 16);
		h1.AsByte().StoreUnsafe(ref output, 32);
		h5.AsByte().StoreUnsafe(ref output, 48);
		h2.AsByte().StoreUnsafe(ref output, 64);
		h6.AsByte().StoreUnsafe(ref output, 80);
		h3.AsByte().StoreUnsafe(ref output, 96);
		h7.AsByte().StoreUnsafe(ref output, 112);
		g0.AsByte().StoreUnsafe(ref output, 128);
		g4.AsByte().StoreUnsafe(ref output, 144);

		if (count > 5)
		{
			g1.AsByte().StoreUnsafe(ref output, 160);
			g5.AsByte().StoreUnsafe(ref output, 176);
		}

		if (count > 6)
		{
			g2.AsByte().StoreUnsafe(ref output, 192);
			g6.AsByte().StoreUnsafe(ref output, 208);
		}

		if (count > 7)
		{
			g3.AsByte().StoreUnsafe(ref output, 224);
			g7.AsByte().StoreUnsafe(ref output, 240);
		}
	}

	// Every call shares the one temporary t: with a temporary of its own per call, the JIT spilled it between the two instructions of a rotation.
	// Rotating by 8 shifts and inserts like the other rotations instead of looking up a table, whose indices would take one more vector register when the
	// two groups already need more than ARM64 has; on Apple M2 this was faster here, though slower in the four-lane kernel.
	// ReSharper disable once RedundantAssignment
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Half
	(
		ref Vector128<uint> a0, ref Vector128<uint> a1, ref Vector128<uint> a2, ref Vector128<uint> a3,
		ref Vector128<uint> b0, ref Vector128<uint> b1, ref Vector128<uint> b2, ref Vector128<uint> b3,
		ref Vector128<uint> c0, ref Vector128<uint> c1, ref Vector128<uint> c2, ref Vector128<uint> c3,
		ref Vector128<uint> d0, ref Vector128<uint> d1, ref Vector128<uint> d2, ref Vector128<uint> d3,
		ref Vector128<uint> t, ref Vector128<uint> message,
		int x0, int x1, int x2, int x3,
		bool first
	)
	{
		a0 = a0 + Unsafe.Add(ref message, x0) + b0;
		a1 = a1 + Unsafe.Add(ref message, x1) + b1;
		a2 = a2 + Unsafe.Add(ref message, x2) + b2;
		a3 = a3 + Unsafe.Add(ref message, x3) + b3;

		if (first)
		{
			d0 = AdvSimd.ReverseElement16(d0 ^ a0);
			d1 = AdvSimd.ReverseElement16(d1 ^ a1);
			d2 = AdvSimd.ReverseElement16(d2 ^ a2);
			d3 = AdvSimd.ReverseElement16(d3 ^ a3);
		}
		else
		{
			t = d0 ^ a0;
			d0 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 24), t, 8);
			t = d1 ^ a1;
			d1 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 24), t, 8);
			t = d2 ^ a2;
			d2 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 24), t, 8);
			t = d3 ^ a3;
			d3 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 24), t, 8);
		}

		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;

		if (first)
		{
			t = b0 ^ c0;
			b0 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 20), t, 12);
			t = b1 ^ c1;
			b1 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 20), t, 12);
			t = b2 ^ c2;
			b2 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 20), t, 12);
			t = b3 ^ c3;
			b3 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 20), t, 12);
		}
		else
		{
			t = b0 ^ c0;
			b0 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 25), t, 7);
			t = b1 ^ c1;
			b1 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 25), t, 7);
			t = b2 ^ c2;
			b2 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 25), t, 7);
			t = b3 ^ c3;
			b3 = AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(t, 25), t, 7);
		}
	}
}
