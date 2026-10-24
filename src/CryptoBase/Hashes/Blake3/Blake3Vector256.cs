using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal readonly struct Blake3Vector256 : IBlake3XofKernel
{
	public static bool IsSupported => Avx2.IsSupported;

	public static int Degree => 8;

	// Four or fewer inputs left over go to the row kernel, which takes fewer instructions per input.
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

		// Four full chunks take the eight lanes only for a partial chunk long enough to pay for them, which is shorter where the scalar compressor hashes it.
		if (count > 4 || count is 4 && tailLength > (Blake3Compressor.PreferScalar ? 4u : 7u) * BlockLength)
		{
			HashLast(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else
		{
			Blake3Vector256Rows.HashChunks(ref input, length, in key, counter, flags, ref output);
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
		else if (count is not 0)
		{
			Blake3Vector256Rows.HashParents(ref input, count, in key, flags, ref output);
		}
	}

	public static void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		for (; count >= 8; count -= 8)
		{
			Xof(in cv, ref block, blockLength, counter, flags, 8, ref output);
			output = ref Unsafe.Add(ref output, 8 * BlockLength);
			counter += 8;
		}

		if (count > 4)
		{
			Xof(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else if (count is not 0)
		{
			Blake3Vector128.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
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

		// Lanes past count rehash the last input, which keeps every load inside the input.
		nuint last = (count - 1) * stride - (tailBlocks is 0 ? 0 : (blockCount - tailBlocks) * BlockLength);
		nuint o1 = stride;
		nuint o2 = 2 * stride;
		nuint o3 = 3 * stride;
		nuint o4 = count > 5 ? 4 * stride : last;
		nuint o5 = count > 6 ? 5 * stride : last;
		nuint o6 = count > 7 ? 6 * stride : last;
		nuint o7 = last;

		ref uint k = ref Unsafe.AsRef(in key);
		Vector256<uint> h0 = Vector256.Create(k);
		Vector256<uint> h1 = Vector256.Create(Unsafe.Add(ref k, 1));
		Vector256<uint> h2 = Vector256.Create(Unsafe.Add(ref k, 2));
		Vector256<uint> h3 = Vector256.Create(Unsafe.Add(ref k, 3));
		Vector256<uint> h4 = Vector256.Create(Unsafe.Add(ref k, 4));
		Vector256<uint> h5 = Vector256.Create(Unsafe.Add(ref k, 5));
		Vector256<uint> h6 = Vector256.Create(Unsafe.Add(ref k, 6));
		Vector256<uint> h7 = Vector256.Create(Unsafe.Add(ref k, 7));
		Vector256<uint> counterLow = Vector256.Create((uint)counter);

		if (chunks)
		{
			counterLow += Vector256<uint>.Indices;
		}

		Vector256<uint> counterHigh = Vector256.Create((uint)(counter >> 32)) - Vector256.LessThan(counterLow, Vector256.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector256<uint>> message);
		uint blockFlags = flags | startFlags;

		// Near its end, an input would prefetch the start of the next input, which another lane has already read; it prefetches the input that its lane hashes in the next batch instead.
		nuint nextBatch = (count - 1) * stride;

		do
		{
			Prefetch(ref input, blockCount > PrefetchDistance / BlockLength ? 0 : nextBatch, o1, o2, o3, o4, o5, o6, o7);
			LoadMessage(ref input, o1, o2, o3, o4, o5, o6, o7, ref message[0]);
			Vector256<uint> laneFlags = Vector256.Create(blockCount is 1 ? blockFlags | endFlags : blockFlags);

			if (blockCount <= tailBlocks)
			{
				Vector256<uint> tail = Vector256.GreaterThan(Vector256<int>.Indices, Vector256.Create((int)count - 2)).AsUInt32();
				uint tailFlags = flags;

				if (blockCount == tailBlocks)
				{
					h0 = Vector256.ConditionalSelect(tail, Vector256.Create(k), h0);
					h1 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 1)), h1);
					h2 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 2)), h2);
					h3 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 3)), h3);
					h4 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 4)), h4);
					h5 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 5)), h5);
					h6 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 6)), h6);
					h7 = Vector256.ConditionalSelect(tail, Vector256.Create(Unsafe.Add(ref k, 7)), h7);
					tailFlags |= startFlags;
				}

				laneFlags = Vector256.ConditionalSelect(tail, Vector256.Create(tailFlags), laneFlags);
			}

			Vector256<uint> v0 = h0;
			Vector256<uint> v1 = h1;
			Vector256<uint> v2 = h2;
			Vector256<uint> v3 = h3;
			Vector256<uint> v4 = h4;
			Vector256<uint> v5 = h5;
			Vector256<uint> v6 = h6;
			Vector256<uint> v7 = h7;
			Vector256<uint> v8 = Vector256.Create(IV0);
			Vector256<uint> v9 = Vector256.Create(IV1);
			Vector256<uint> v10 = Vector256.Create(IV2);
			Vector256<uint> v11 = Vector256.Create(IV3);
			Vector256<uint> v12 = counterLow;
			Vector256<uint> v13 = counterHigh;
			Vector256<uint> v14 = Vector256.Create((uint)BlockLength);
			Vector256<uint> v15 = laneFlags;

			Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message[0]);

			h0 = v0 ^ v8;
			h1 = v1 ^ v9;
			h2 = v2 ^ v10;
			h3 = v3 ^ v11;
			h4 = v4 ^ v12;
			h5 = v5 ^ v13;
			h6 = v6 ^ v14;
			h7 = v7 ^ v15;

			blockFlags = flags;
			input = ref Unsafe.Add(ref input, BlockLength);
		} while (--blockCount is not 0);

		VectorTranspose.Transpose(ref h0, ref h1, ref h2, ref h3, ref h4, ref h5, ref h6, ref h7);

		h0.AsByte().StoreUnsafe(ref output);
		h1.AsByte().StoreUnsafe(ref output, 32);
		h2.AsByte().StoreUnsafe(ref output, 64);
		h3.AsByte().StoreUnsafe(ref output, 96);
		h4.AsByte().StoreUnsafe(ref output, 128);

		if (count > 5)
		{
			h5.AsByte().StoreUnsafe(ref output, 160);
		}

		if (count > 6)
		{
			h6.AsByte().StoreUnsafe(ref output, 192);
		}

		if (count > 7)
		{
			h7.AsByte().StoreUnsafe(ref output, 224);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Xof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		Debug.Assert(count is > 4 and <= 8);

		Unsafe.SkipInit(out InlineArray16<Vector256<uint>> message);

		for (int i = 0; i < 16; ++i)
		{
			message[i] = Vector256.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, i * sizeof(uint))));
		}

		ref uint h = ref Unsafe.AsRef(in cv);
		Vector256<uint> v0 = Vector256.Create(h);
		Vector256<uint> v1 = Vector256.Create(Unsafe.Add(ref h, 1));
		Vector256<uint> v2 = Vector256.Create(Unsafe.Add(ref h, 2));
		Vector256<uint> v3 = Vector256.Create(Unsafe.Add(ref h, 3));
		Vector256<uint> v4 = Vector256.Create(Unsafe.Add(ref h, 4));
		Vector256<uint> v5 = Vector256.Create(Unsafe.Add(ref h, 5));
		Vector256<uint> v6 = Vector256.Create(Unsafe.Add(ref h, 6));
		Vector256<uint> v7 = Vector256.Create(Unsafe.Add(ref h, 7));
		Vector256<uint> v8 = Vector256.Create(IV0);
		Vector256<uint> v9 = Vector256.Create(IV1);
		Vector256<uint> v10 = Vector256.Create(IV2);
		Vector256<uint> v11 = Vector256.Create(IV3);
		Vector256<uint> v12 = Vector256.Create((uint)counter) + Vector256<uint>.Indices;
		Vector256<uint> v13 = Vector256.Create((uint)(counter >> 32)) - Vector256.LessThan(v12, Vector256.Create((uint)counter));
		Vector256<uint> v14 = Vector256.Create(blockLength);
		Vector256<uint> v15 = Vector256.Create(flags);

		Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message[0]);

		Vector256<uint> o0 = v0 ^ v8;
		Vector256<uint> o1 = v1 ^ v9;
		Vector256<uint> o2 = v2 ^ v10;
		Vector256<uint> o3 = v3 ^ v11;
		Vector256<uint> o4 = v4 ^ v12;
		Vector256<uint> o5 = v5 ^ v13;
		Vector256<uint> o6 = v6 ^ v14;
		Vector256<uint> o7 = v7 ^ v15;
		Vector256<uint> o8 = v8 ^ Vector256.Create(h);
		Vector256<uint> o9 = v9 ^ Vector256.Create(Unsafe.Add(ref h, 1));
		Vector256<uint> o10 = v10 ^ Vector256.Create(Unsafe.Add(ref h, 2));
		Vector256<uint> o11 = v11 ^ Vector256.Create(Unsafe.Add(ref h, 3));
		Vector256<uint> o12 = v12 ^ Vector256.Create(Unsafe.Add(ref h, 4));
		Vector256<uint> o13 = v13 ^ Vector256.Create(Unsafe.Add(ref h, 5));
		Vector256<uint> o14 = v14 ^ Vector256.Create(Unsafe.Add(ref h, 6));
		Vector256<uint> o15 = v15 ^ Vector256.Create(Unsafe.Add(ref h, 7));

		VectorTranspose.Transpose(ref o0, ref o1, ref o2, ref o3, ref o4, ref o5, ref o6, ref o7);
		VectorTranspose.Transpose(ref o8, ref o9, ref o10, ref o11, ref o12, ref o13, ref o14, ref o15);

		StoreBlock(o0, o8, ref output);
		StoreBlock(o1, o9, ref Unsafe.Add(ref output, BlockLength));
		StoreBlock(o2, o10, ref Unsafe.Add(ref output, 2 * BlockLength));
		StoreBlock(o3, o11, ref Unsafe.Add(ref output, 3 * BlockLength));
		StoreBlock(o4, o12, ref Unsafe.Add(ref output, 4 * BlockLength));

		if (count > 5)
		{
			StoreBlock(o5, o13, ref Unsafe.Add(ref output, 5 * BlockLength));
		}

		if (count > 6)
		{
			StoreBlock(o6, o14, ref Unsafe.Add(ref output, 6 * BlockLength));
		}

		if (count > 7)
		{
			StoreBlock(o7, o15, ref Unsafe.Add(ref output, 7 * BlockLength));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadMessage(ref byte block, nuint o1, nuint o2, nuint o3, nuint o4, nuint o5, nuint o6, nuint o7, ref Vector256<uint> message)
	{
		LoadWords(ref block, o1, o2, o3, o4, o5, o6, o7, ref message);
		LoadWords(ref Unsafe.Add(ref block, 16), o1, o2, o3, o4, o5, o6, o7, ref Unsafe.Add(ref message, 4));
		LoadWords(ref Unsafe.Add(ref block, 32), o1, o2, o3, o4, o5, o6, o7, ref Unsafe.Add(ref message, 8));
		LoadWords(ref Unsafe.Add(ref block, 48), o1, o2, o3, o4, o5, o6, o7, ref Unsafe.Add(ref message, 12));
	}

	// Loads four words of each input as four vectors. Inputs i and i + 4 share a row, input i + 4 in the high lane, which leaves only a 4x4 transpose within each lane: the loads, not lane-crossing shuffles, put the inputs into place.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadWords(ref byte block, nuint o1, nuint o2, nuint o3, nuint o4, nuint o5, nuint o6, nuint o7, ref Vector256<uint> message)
	{
		Vector256<uint> r0 = Vector256.Create(Vector128.LoadUnsafe(ref block), Vector128.LoadUnsafe(ref block, o4)).AsUInt32();
		Vector256<uint> r1 = Vector256.Create(Vector128.LoadUnsafe(ref block, o1), Vector128.LoadUnsafe(ref block, o5)).AsUInt32();
		Vector256<uint> r2 = Vector256.Create(Vector128.LoadUnsafe(ref block, o2), Vector128.LoadUnsafe(ref block, o6)).AsUInt32();
		Vector256<uint> r3 = Vector256.Create(Vector128.LoadUnsafe(ref block, o3), Vector128.LoadUnsafe(ref block, o7)).AsUInt32();
		Vector256<ulong> t0 = Avx2.UnpackLow(r0, r1).AsUInt64();
		Vector256<ulong> t1 = Avx2.UnpackLow(r2, r3).AsUInt64();
		Vector256<ulong> t2 = Avx2.UnpackHigh(r0, r1).AsUInt64();
		Vector256<ulong> t3 = Avx2.UnpackHigh(r2, r3).AsUInt64();
		Unsafe.Add(ref message, 0) = Avx2.UnpackLow(t0, t1).AsUInt32();
		Unsafe.Add(ref message, 1) = Avx2.UnpackHigh(t0, t1).AsUInt32();
		Unsafe.Add(ref message, 2) = Avx2.UnpackLow(t2, t3).AsUInt32();
		Unsafe.Add(ref message, 3) = Avx2.UnpackHigh(t2, t3).AsUInt32();
	}

	// A prefetch never faults and is only a hint, so its address may lie past the input and needs no pinning: if the input moves meanwhile, the hint is merely wasted.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Prefetch(ref byte block, nuint skip, nuint o1, nuint o2, nuint o3, nuint o4, nuint o5, nuint o6, nuint o7)
	{
		byte* ahead = (byte*)Unsafe.AsPointer(ref block) + PrefetchDistance + skip;
		Sse.Prefetch0(ahead);
		Sse.Prefetch0(ahead + o1);
		Sse.Prefetch0(ahead + o2);
		Sse.Prefetch0(ahead + o3);
		Sse.Prefetch0(ahead + o4);
		Sse.Prefetch0(ahead + o5);
		Sse.Prefetch0(ahead + o6);
		Sse.Prefetch0(ahead + o7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreBlock(Vector256<uint> low, Vector256<uint> high, ref byte output)
	{
		low.AsByte().StoreUnsafe(ref output);
		high.AsByte().StoreUnsafe(ref output, 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds
	(
		ref Vector256<uint> v0, ref Vector256<uint> v1, ref Vector256<uint> v2, ref Vector256<uint> v3,
		ref Vector256<uint> v4, ref Vector256<uint> v5, ref Vector256<uint> v6, ref Vector256<uint> v7,
		ref Vector256<uint> v8, ref Vector256<uint> v9, ref Vector256<uint> v10, ref Vector256<uint> v11,
		ref Vector256<uint> v12, ref Vector256<uint> v13, ref Vector256<uint> v14, ref Vector256<uint> v15,
		ref Vector256<uint> message
	)
	{
		if (Avx512F.VL.IsSupported)
		{
			RoundsAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message);
			return;
		}

		ref byte schedule = ref MemoryMarshal.GetReference(MessageSchedule);

		// A loop keeps the kernel small enough for the JIT to inline every step and rotation, whatever instructions the rotations take.
		for (int round = 0; round < Blake3Constants.Rounds; ++round)
		{
			ref byte words = ref Unsafe.Add(ref schedule, round * 16);
			Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, ref words);
			Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, ref Unsafe.Add(ref words, 8));
		}
	}

	// Unrolled, so that every message word has a constant index; each rotation is a single AVX-512VL instruction, so all fourteen steps still inline.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundsAvx512Vl
	(
		ref Vector256<uint> v0, ref Vector256<uint> v1, ref Vector256<uint> v2, ref Vector256<uint> v3,
		ref Vector256<uint> v4, ref Vector256<uint> v5, ref Vector256<uint> v6, ref Vector256<uint> v7,
		ref Vector256<uint> v8, ref Vector256<uint> v9, ref Vector256<uint> v10, ref Vector256<uint> v11,
		ref Vector256<uint> v12, ref Vector256<uint> v13, ref Vector256<uint> v14, ref Vector256<uint> v15,
		ref Vector256<uint> message
	)
	{
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 0, 2, 4, 6, 1, 3, 5, 7);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 8, 10, 12, 14, 9, 11, 13, 15);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 2, 3, 7, 4, 6, 10, 0, 13);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 1, 12, 9, 15, 11, 5, 14, 8);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 3, 10, 13, 7, 4, 12, 2, 14);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 6, 9, 11, 8, 5, 0, 15, 1);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 10, 12, 14, 13, 7, 9, 3, 15);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 4, 11, 5, 1, 0, 2, 8, 6);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 12, 9, 15, 14, 13, 11, 10, 8);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 7, 5, 0, 6, 2, 3, 1, 4);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 9, 11, 8, 15, 14, 5, 12, 1);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 13, 0, 2, 4, 3, 10, 6, 7);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 11, 5, 1, 8, 15, 0, 9, 6);
		StepAvx512Vl(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 14, 2, 3, 7, 10, 12, 4, 13);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StepAvx512Vl
	(
		ref Vector256<uint> a0, ref Vector256<uint> a1, ref Vector256<uint> a2, ref Vector256<uint> a3,
		ref Vector256<uint> b0, ref Vector256<uint> b1, ref Vector256<uint> b2, ref Vector256<uint> b3,
		ref Vector256<uint> c0, ref Vector256<uint> c1, ref Vector256<uint> c2, ref Vector256<uint> c3,
		ref Vector256<uint> d0, ref Vector256<uint> d1, ref Vector256<uint> d2, ref Vector256<uint> d3,
		ref Vector256<uint> message,
		int x0, int x1, int x2, int x3,
		int y0, int y1, int y2, int y3
	)
	{
		a0 = a0 + Unsafe.Add(ref message, x0) + b0;
		a1 = a1 + Unsafe.Add(ref message, x1) + b1;
		a2 = a2 + Unsafe.Add(ref message, x2) + b2;
		a3 = a3 + Unsafe.Add(ref message, x3) + b3;
		d0 = Avx512F.VL.RotateRight(d0 ^ a0, 16);
		d1 = Avx512F.VL.RotateRight(d1 ^ a1, 16);
		d2 = Avx512F.VL.RotateRight(d2 ^ a2, 16);
		d3 = Avx512F.VL.RotateRight(d3 ^ a3, 16);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = Avx512F.VL.RotateRight(b0 ^ c0, 12);
		b1 = Avx512F.VL.RotateRight(b1 ^ c1, 12);
		b2 = Avx512F.VL.RotateRight(b2 ^ c2, 12);
		b3 = Avx512F.VL.RotateRight(b3 ^ c3, 12);
		a0 = a0 + Unsafe.Add(ref message, y0) + b0;
		a1 = a1 + Unsafe.Add(ref message, y1) + b1;
		a2 = a2 + Unsafe.Add(ref message, y2) + b2;
		a3 = a3 + Unsafe.Add(ref message, y3) + b3;
		d0 = Avx512F.VL.RotateRight(d0 ^ a0, 8);
		d1 = Avx512F.VL.RotateRight(d1 ^ a1, 8);
		d2 = Avx512F.VL.RotateRight(d2 ^ a2, 8);
		d3 = Avx512F.VL.RotateRight(d3 ^ a3, 8);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = Avx512F.VL.RotateRight(b0 ^ c0, 7);
		b1 = Avx512F.VL.RotateRight(b1 ^ c1, 7);
		b2 = Avx512F.VL.RotateRight(b2 ^ c2, 7);
		b3 = Avx512F.VL.RotateRight(b3 ^ c3, 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<uint> Word(ref Vector256<uint> message, ref byte words, int i)
	{
		return Unsafe.Add(ref message, Unsafe.Add(ref words, i));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step
	(
		ref Vector256<uint> a0, ref Vector256<uint> a1, ref Vector256<uint> a2, ref Vector256<uint> a3,
		ref Vector256<uint> b0, ref Vector256<uint> b1, ref Vector256<uint> b2, ref Vector256<uint> b3,
		ref Vector256<uint> c0, ref Vector256<uint> c1, ref Vector256<uint> c2, ref Vector256<uint> c3,
		ref Vector256<uint> d0, ref Vector256<uint> d1, ref Vector256<uint> d2, ref Vector256<uint> d3,
		ref Vector256<uint> message, ref byte words
	)
	{
		a0 = a0 + Word(ref message, ref words, 0) + b0;
		a1 = a1 + Word(ref message, ref words, 1) + b1;
		a2 = a2 + Word(ref message, ref words, 2) + b2;
		a3 = a3 + Word(ref message, ref words, 3) + b3;
		d0 = (d0 ^ a0).RotateRightUInt32(16);
		d1 = (d1 ^ a1).RotateRightUInt32(16);
		d2 = (d2 ^ a2).RotateRightUInt32(16);
		d3 = (d3 ^ a3).RotateRightUInt32(16);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = (b0 ^ c0).RotateRightUInt32(12);
		b1 = (b1 ^ c1).RotateRightUInt32(12);
		b2 = (b2 ^ c2).RotateRightUInt32(12);
		b3 = (b3 ^ c3).RotateRightUInt32(12);
		a0 = a0 + Word(ref message, ref words, 4) + b0;
		a1 = a1 + Word(ref message, ref words, 5) + b1;
		a2 = a2 + Word(ref message, ref words, 6) + b2;
		a3 = a3 + Word(ref message, ref words, 7) + b3;
		d0 = (d0 ^ a0).RotateRightUInt32(8);
		d1 = (d1 ^ a1).RotateRightUInt32(8);
		d2 = (d2 ^ a2).RotateRightUInt32(8);
		d3 = (d3 ^ a3).RotateRightUInt32(8);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = (b0 ^ c0).RotateRightUInt32(7);
		b1 = (b1 ^ c1).RotateRightUInt32(7);
		b2 = (b2 ^ c2).RotateRightUInt32(7);
		b3 = (b3 ^ c3).RotateRightUInt32(7);
	}
}
