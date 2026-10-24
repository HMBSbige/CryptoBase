using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal readonly struct Blake3Vector512 : IBlake3XofKernel
{
	public static bool IsSupported => Vector512.IsHardwareAccelerated && Avx512F.IsSupported;

	public static int Degree => 16;

	// Eight or fewer inputs left over go to an eight-lane kernel, which takes no more instructions per input on any AVX-512 core and fewer cycles on cores that split 512-bit operations.
	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length > 16 * ChunkLength; length -= 16 * ChunkLength)
		{
			HashFull(ref input, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 16 * ChunkLength);
			output = ref Unsafe.Add(ref output, 16 * OutLength);
			counter += 16;
		}

		nuint count = length / ChunkLength;
		nuint tailLength = length % ChunkLength;

		// Eight full chunks take the sixteen lanes only for a partial chunk long enough to pay for them.
		if (count > 8 || count is 8 && tailLength > 5 * BlockLength)
		{
			HashLast(ref input, count, tailLength, in key, counter, flags, ref output);
		}
		else if (Blake3Vector512Rows.IsPreferred)
		{
			Blake3Vector512Rows.HashChunks(ref input, length, in key, counter, flags, ref output);
		}
		else
		{
			Blake3Vector256.HashChunks(ref input, length, in key, counter, flags, ref output);
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		for (; count >= 16; count -= 16)
		{
			Hash(ref input, 16, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
			input = ref Unsafe.Add(ref input, 16 * BlockLength);
			output = ref Unsafe.Add(ref output, 16 * OutLength);
		}

		if (count > 8)
		{
			Hash(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (Blake3Vector512Rows.IsPreferred)
		{
			Blake3Vector512Rows.HashParents(ref input, count, in key, flags, ref output);
		}
		else
		{
			Blake3Vector256.HashParents(ref input, count, in key, flags, ref output);
		}
	}

	public static void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		for (; count >= 16; count -= 16)
		{
			Xof(in cv, ref block, blockLength, counter, flags, 16, ref output);
			output = ref Unsafe.Add(ref output, 16 * BlockLength);
			counter += 16;
		}

		if (count > 8)
		{
			Xof(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else if (count is not 0)
		{
			Blake3Vector256.XofMany(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
	}

	private static void HashLast(ref byte input, nuint count, nuint tailLength, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		if (count is 16)
		{
			HashFull(ref input, in key, counter, flags, ref output);
			return;
		}

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

		Debug.Assert(count is > 8 and <= 16);
		Debug.Assert(tailBlocks < blockCount);

		// Lanes past count rehash the last input, which keeps every load inside the input.
		Unsafe.SkipInit(out InlineArray16<nuint> offsets);
		nuint lastOffset = (count - 1) * stride - (tailBlocks is 0 ? 0 : (blockCount - tailBlocks) * BlockLength);

		for (int i = 0; i < 16; ++i)
		{
			offsets[i] = (nuint)i < count - 1 ? (nuint)i * stride : lastOffset;
		}

		ref uint k = ref Unsafe.AsRef(in key);
		Vector512<uint> h0 = Vector512.Create(k);
		Vector512<uint> h1 = Vector512.Create(Unsafe.Add(ref k, 1));
		Vector512<uint> h2 = Vector512.Create(Unsafe.Add(ref k, 2));
		Vector512<uint> h3 = Vector512.Create(Unsafe.Add(ref k, 3));
		Vector512<uint> h4 = Vector512.Create(Unsafe.Add(ref k, 4));
		Vector512<uint> h5 = Vector512.Create(Unsafe.Add(ref k, 5));
		Vector512<uint> h6 = Vector512.Create(Unsafe.Add(ref k, 6));
		Vector512<uint> h7 = Vector512.Create(Unsafe.Add(ref k, 7));
		Vector512<uint> counterLow = Vector512.Create((uint)counter);

		if (chunks)
		{
			counterLow += Vector512<uint>.Indices;
		}

		Vector512<uint> counterHigh = Vector512.Create((uint)(counter >> 32)) - Vector512.LessThan(counterLow, Vector512.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> message);
		uint blockFlags = flags | startFlags;

		// Near its end, an input would prefetch the start of the next input, which another lane has already read; it prefetches the input that its lane hashes in the next batch instead.
		nuint nextBatch = (count - 1) * stride;

		do
		{
			Prefetch(ref input, blockCount > PrefetchDistance / BlockLength ? 0 : nextBatch, ref offsets[0]);
			LoadMessage(ref input, ref offsets[0], ref message[0]);
			Vector512<uint> laneFlags = Vector512.Create(blockCount is 1 ? blockFlags | endFlags : blockFlags);

			if (blockCount <= tailBlocks)
			{
				Vector512<uint> tail = Vector512.GreaterThanOrEqual(Vector512<uint>.Indices, Vector512.Create((uint)count - 1));
				uint tailFlags = flags;

				if (blockCount == tailBlocks)
				{
					h0 = Vector512.ConditionalSelect(tail, Vector512.Create(k), h0);
					h1 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 1)), h1);
					h2 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 2)), h2);
					h3 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 3)), h3);
					h4 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 4)), h4);
					h5 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 5)), h5);
					h6 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 6)), h6);
					h7 = Vector512.ConditionalSelect(tail, Vector512.Create(Unsafe.Add(ref k, 7)), h7);
					tailFlags |= startFlags;
				}

				laneFlags = Vector512.ConditionalSelect(tail, Vector512.Create(tailFlags), laneFlags);
			}

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
			Vector512<uint> v12 = counterLow;
			Vector512<uint> v13 = counterHigh;
			Vector512<uint> v14 = Vector512.Create((uint)BlockLength);
			Vector512<uint> v15 = laneFlags;

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

		Unsafe.SkipInit(out InlineArray16<Vector256<uint>> chainingValues);
		bool partial = count is not 16;
		ref byte destination = ref partial ? ref Unsafe.As<Vector256<uint>, byte>(ref chainingValues[0]) : ref output;
		StoreChainingValues(h0, h1, h2, h3, h4, h5, h6, h7, ref destination);

		if (partial)
		{
			Unsafe.CopyBlockUnaligned(ref output, ref destination, (uint)count * OutLength);
		}
	}

	// Hashes sixteen consecutive full chunks as Hash does, without its offsets in memory: the loads and prefetches take constant offsets, and no lane takes the steps of a partial chunk.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void HashFull(ref byte input, ref readonly uint key, ulong counter, uint flags, ref byte output)
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
		Vector512<uint> counterLow = Vector512.Create((uint)counter) + Vector512<uint>.Indices;
		Vector512<uint> counterHigh = Vector512.Create((uint)(counter >> 32)) - Vector512.LessThan(counterLow, Vector512.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> message);
		uint blockFlags = flags | Blake3Flags.ChunkStart;
		nuint blockCount = ChunkBlocks;

		// Near the end of the chunks, each lane prefetches the chunk that it hashes in the next batch, as in Hash.
		nuint nextBatch = 15 * ChunkLength;

		do
		{
			PrefetchFull(ref input, blockCount > PrefetchDistance / BlockLength ? 0 : nextBatch);
			LoadMessageFull(ref input, ref message[0]);
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
			Vector512<uint> v12 = counterLow;
			Vector512<uint> v13 = counterHigh;
			Vector512<uint> v14 = Vector512.Create((uint)BlockLength);
			Vector512<uint> v15 = laneFlags;

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

		StoreChainingValues(h0, h1, h2, h3, h4, h5, h6, h7, ref output);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Xof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		Debug.Assert(count is > 8 and <= 16);

		// Constant indices, as in LoadMessage, let the message stay in registers.
		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> message);
		message[0] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref block));
		message[1] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 4)));
		message[2] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 8)));
		message[3] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 12)));
		message[4] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 16)));
		message[5] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 20)));
		message[6] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 24)));
		message[7] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 28)));
		message[8] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 32)));
		message[9] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 36)));
		message[10] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 40)));
		message[11] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 44)));
		message[12] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 48)));
		message[13] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 52)));
		message[14] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 56)));
		message[15] = Vector512.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, 60)));

		ref uint h = ref Unsafe.AsRef(in cv);
		Vector512<uint> v0 = Vector512.Create(h);
		Vector512<uint> v1 = Vector512.Create(Unsafe.Add(ref h, 1));
		Vector512<uint> v2 = Vector512.Create(Unsafe.Add(ref h, 2));
		Vector512<uint> v3 = Vector512.Create(Unsafe.Add(ref h, 3));
		Vector512<uint> v4 = Vector512.Create(Unsafe.Add(ref h, 4));
		Vector512<uint> v5 = Vector512.Create(Unsafe.Add(ref h, 5));
		Vector512<uint> v6 = Vector512.Create(Unsafe.Add(ref h, 6));
		Vector512<uint> v7 = Vector512.Create(Unsafe.Add(ref h, 7));
		Vector512<uint> v8 = Vector512.Create(IV0);
		Vector512<uint> v9 = Vector512.Create(IV1);
		Vector512<uint> v10 = Vector512.Create(IV2);
		Vector512<uint> v11 = Vector512.Create(IV3);
		Vector512<uint> v12 = Vector512.Create((uint)counter) + Vector512<uint>.Indices;
		Vector512<uint> v13 = Vector512.Create((uint)(counter >> 32)) - Vector512.LessThan(v12, Vector512.Create((uint)counter));
		Vector512<uint> v14 = Vector512.Create(blockLength);
		Vector512<uint> v15 = Vector512.Create(flags);

		Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message[0]);

		Vector512<uint> o0 = v0 ^ v8;
		Vector512<uint> o1 = v1 ^ v9;
		Vector512<uint> o2 = v2 ^ v10;
		Vector512<uint> o3 = v3 ^ v11;
		Vector512<uint> o4 = v4 ^ v12;
		Vector512<uint> o5 = v5 ^ v13;
		Vector512<uint> o6 = v6 ^ v14;
		Vector512<uint> o7 = v7 ^ v15;
		Vector512<uint> o8 = v8 ^ Vector512.Create(h);
		Vector512<uint> o9 = v9 ^ Vector512.Create(Unsafe.Add(ref h, 1));
		Vector512<uint> o10 = v10 ^ Vector512.Create(Unsafe.Add(ref h, 2));
		Vector512<uint> o11 = v11 ^ Vector512.Create(Unsafe.Add(ref h, 3));
		Vector512<uint> o12 = v12 ^ Vector512.Create(Unsafe.Add(ref h, 4));
		Vector512<uint> o13 = v13 ^ Vector512.Create(Unsafe.Add(ref h, 5));
		Vector512<uint> o14 = v14 ^ Vector512.Create(Unsafe.Add(ref h, 6));
		Vector512<uint> o15 = v15 ^ Vector512.Create(Unsafe.Add(ref h, 7));

		VectorTranspose.Transpose(ref o0, ref o1, ref o2, ref o3, ref o4, ref o5, ref o6, ref o7, ref o8, ref o9, ref o10, ref o11, ref o12, ref o13, ref o14, ref o15);

		Unsafe.SkipInit(out InlineArray16<Vector512<uint>> blocks);
		bool partial = count is not 16;
		ref byte destination = ref partial ? ref Unsafe.As<Vector512<uint>, byte>(ref blocks[0]) : ref output;

		o0.AsByte().StoreUnsafe(ref destination);
		o1.AsByte().StoreUnsafe(ref destination, 64);
		o2.AsByte().StoreUnsafe(ref destination, 128);
		o3.AsByte().StoreUnsafe(ref destination, 192);
		o4.AsByte().StoreUnsafe(ref destination, 256);
		o5.AsByte().StoreUnsafe(ref destination, 320);
		o6.AsByte().StoreUnsafe(ref destination, 384);
		o7.AsByte().StoreUnsafe(ref destination, 448);
		o8.AsByte().StoreUnsafe(ref destination, 512);
		o9.AsByte().StoreUnsafe(ref destination, 576);
		o10.AsByte().StoreUnsafe(ref destination, 640);
		o11.AsByte().StoreUnsafe(ref destination, 704);
		o12.AsByte().StoreUnsafe(ref destination, 768);
		o13.AsByte().StoreUnsafe(ref destination, 832);
		o14.AsByte().StoreUnsafe(ref destination, 896);
		o15.AsByte().StoreUnsafe(ref destination, 960);

		if (partial)
		{
			Unsafe.CopyBlockUnaligned(ref output, ref destination, (uint)count * BlockLength);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadMessage(ref byte block, ref nuint offsets, ref Vector512<uint> message)
	{
		Vector512<uint> m0 = Vector512.LoadUnsafe(ref block, offsets).AsUInt32();
		Vector512<uint> m1 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 1)).AsUInt32();
		Vector512<uint> m2 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 2)).AsUInt32();
		Vector512<uint> m3 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 3)).AsUInt32();
		Vector512<uint> m4 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 4)).AsUInt32();
		Vector512<uint> m5 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 5)).AsUInt32();
		Vector512<uint> m6 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 6)).AsUInt32();
		Vector512<uint> m7 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 7)).AsUInt32();
		Vector512<uint> m8 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 8)).AsUInt32();
		Vector512<uint> m9 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 9)).AsUInt32();
		Vector512<uint> m10 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 10)).AsUInt32();
		Vector512<uint> m11 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 11)).AsUInt32();
		Vector512<uint> m12 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 12)).AsUInt32();
		Vector512<uint> m13 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 13)).AsUInt32();
		Vector512<uint> m14 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 14)).AsUInt32();
		Vector512<uint> m15 = Vector512.LoadUnsafe(ref block, Unsafe.Add(ref offsets, 15)).AsUInt32();
		VectorTranspose.Transpose(ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7, ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
		Unsafe.Add(ref message, 0) = m0;
		Unsafe.Add(ref message, 1) = m1;
		Unsafe.Add(ref message, 2) = m2;
		Unsafe.Add(ref message, 3) = m3;
		Unsafe.Add(ref message, 4) = m4;
		Unsafe.Add(ref message, 5) = m5;
		Unsafe.Add(ref message, 6) = m6;
		Unsafe.Add(ref message, 7) = m7;
		Unsafe.Add(ref message, 8) = m8;
		Unsafe.Add(ref message, 9) = m9;
		Unsafe.Add(ref message, 10) = m10;
		Unsafe.Add(ref message, 11) = m11;
		Unsafe.Add(ref message, 12) = m12;
		Unsafe.Add(ref message, 13) = m13;
		Unsafe.Add(ref message, 14) = m14;
		Unsafe.Add(ref message, 15) = m15;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadMessageFull(ref byte block, ref Vector512<uint> message)
	{
		Vector512<uint> m0 = Vector512.LoadUnsafe(ref block).AsUInt32();
		Vector512<uint> m1 = Vector512.LoadUnsafe(ref block, ChunkLength).AsUInt32();
		Vector512<uint> m2 = Vector512.LoadUnsafe(ref block, 2 * ChunkLength).AsUInt32();
		Vector512<uint> m3 = Vector512.LoadUnsafe(ref block, 3 * ChunkLength).AsUInt32();
		Vector512<uint> m4 = Vector512.LoadUnsafe(ref block, 4 * ChunkLength).AsUInt32();
		Vector512<uint> m5 = Vector512.LoadUnsafe(ref block, 5 * ChunkLength).AsUInt32();
		Vector512<uint> m6 = Vector512.LoadUnsafe(ref block, 6 * ChunkLength).AsUInt32();
		Vector512<uint> m7 = Vector512.LoadUnsafe(ref block, 7 * ChunkLength).AsUInt32();
		Vector512<uint> m8 = Vector512.LoadUnsafe(ref block, 8 * ChunkLength).AsUInt32();
		Vector512<uint> m9 = Vector512.LoadUnsafe(ref block, 9 * ChunkLength).AsUInt32();
		Vector512<uint> m10 = Vector512.LoadUnsafe(ref block, 10 * ChunkLength).AsUInt32();
		Vector512<uint> m11 = Vector512.LoadUnsafe(ref block, 11 * ChunkLength).AsUInt32();
		Vector512<uint> m12 = Vector512.LoadUnsafe(ref block, 12 * ChunkLength).AsUInt32();
		Vector512<uint> m13 = Vector512.LoadUnsafe(ref block, 13 * ChunkLength).AsUInt32();
		Vector512<uint> m14 = Vector512.LoadUnsafe(ref block, 14 * ChunkLength).AsUInt32();
		Vector512<uint> m15 = Vector512.LoadUnsafe(ref block, 15 * ChunkLength).AsUInt32();
		VectorTranspose.Transpose(ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7, ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
		Unsafe.Add(ref message, 0) = m0;
		Unsafe.Add(ref message, 1) = m1;
		Unsafe.Add(ref message, 2) = m2;
		Unsafe.Add(ref message, 3) = m3;
		Unsafe.Add(ref message, 4) = m4;
		Unsafe.Add(ref message, 5) = m5;
		Unsafe.Add(ref message, 6) = m6;
		Unsafe.Add(ref message, 7) = m7;
		Unsafe.Add(ref message, 8) = m8;
		Unsafe.Add(ref message, 9) = m9;
		Unsafe.Add(ref message, 10) = m10;
		Unsafe.Add(ref message, 11) = m11;
		Unsafe.Add(ref message, 12) = m12;
		Unsafe.Add(ref message, 13) = m13;
		Unsafe.Add(ref message, 14) = m14;
		Unsafe.Add(ref message, 15) = m15;
	}

	// A prefetch never faults and is only a hint, so its address may lie past the input and needs no pinning: if the input moves meanwhile, the hint is merely wasted.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void Prefetch(ref byte block, nuint skip, ref nuint offsets)
	{
		byte* ahead = (byte*)Unsafe.AsPointer(ref block) + PrefetchDistance + skip;
		Sse.Prefetch0(ahead + offsets);
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 1));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 2));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 3));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 4));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 5));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 6));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 7));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 8));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 9));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 10));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 11));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 12));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 13));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 14));
		Sse.Prefetch0(ahead + Unsafe.Add(ref offsets, 15));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe void PrefetchFull(ref byte block, nuint skip)
	{
		byte* ahead = (byte*)Unsafe.AsPointer(ref block) + PrefetchDistance + skip;
		Sse.Prefetch0(ahead);
		Sse.Prefetch0(ahead + ChunkLength);
		Sse.Prefetch0(ahead + 2 * ChunkLength);
		Sse.Prefetch0(ahead + 3 * ChunkLength);
		Sse.Prefetch0(ahead + 4 * ChunkLength);
		Sse.Prefetch0(ahead + 5 * ChunkLength);
		Sse.Prefetch0(ahead + 6 * ChunkLength);
		Sse.Prefetch0(ahead + 7 * ChunkLength);
		Sse.Prefetch0(ahead + 8 * ChunkLength);
		Sse.Prefetch0(ahead + 9 * ChunkLength);
		Sse.Prefetch0(ahead + 10 * ChunkLength);
		Sse.Prefetch0(ahead + 11 * ChunkLength);
		Sse.Prefetch0(ahead + 12 * ChunkLength);
		Sse.Prefetch0(ahead + 13 * ChunkLength);
		Sse.Prefetch0(ahead + 14 * ChunkLength);
		Sse.Prefetch0(ahead + 15 * ChunkLength);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void StoreChainingValues(Vector512<uint> h0, Vector512<uint> h1, Vector512<uint> h2, Vector512<uint> h3, Vector512<uint> h4, Vector512<uint> h5, Vector512<uint> h6, Vector512<uint> h7, ref byte output)
	{
		Vector512<ulong> a0 = Avx512F.UnpackLow(h0, h1).AsUInt64();
		Vector512<ulong> a1 = Avx512F.UnpackHigh(h0, h1).AsUInt64();
		Vector512<ulong> a2 = Avx512F.UnpackLow(h2, h3).AsUInt64();
		Vector512<ulong> a3 = Avx512F.UnpackHigh(h2, h3).AsUInt64();
		Vector512<ulong> a4 = Avx512F.UnpackLow(h4, h5).AsUInt64();
		Vector512<ulong> a5 = Avx512F.UnpackHigh(h4, h5).AsUInt64();
		Vector512<ulong> a6 = Avx512F.UnpackLow(h6, h7).AsUInt64();
		Vector512<ulong> a7 = Avx512F.UnpackHigh(h6, h7).AsUInt64();

		Vector512<ulong> b0 = Avx512F.UnpackLow(a0, a2);
		Vector512<ulong> b1 = Avx512F.UnpackHigh(a0, a2);
		Vector512<ulong> b2 = Avx512F.UnpackLow(a1, a3);
		Vector512<ulong> b3 = Avx512F.UnpackHigh(a1, a3);
		Vector512<ulong> b4 = Avx512F.UnpackLow(a4, a6);
		Vector512<ulong> b5 = Avx512F.UnpackHigh(a4, a6);
		Vector512<ulong> b6 = Avx512F.UnpackLow(a5, a7);
		Vector512<ulong> b7 = Avx512F.UnpackHigh(a5, a7);

		Vector512<ulong> lowBlocks = Vector512.Create(0UL, 1, 8, 9, 2, 3, 10, 11);
		Vector512<ulong> highBlocks = Vector512.Create(4UL, 5, 12, 13, 6, 7, 14, 15);
		Vector512<ulong> c0 = Avx512F.PermuteVar8x64x2(b0, lowBlocks, b4);
		Vector512<ulong> c1 = Avx512F.PermuteVar8x64x2(b1, lowBlocks, b5);
		Vector512<ulong> c2 = Avx512F.PermuteVar8x64x2(b2, lowBlocks, b6);
		Vector512<ulong> c3 = Avx512F.PermuteVar8x64x2(b3, lowBlocks, b7);
		Vector512<ulong> c4 = Avx512F.PermuteVar8x64x2(b0, highBlocks, b4);
		Vector512<ulong> c5 = Avx512F.PermuteVar8x64x2(b1, highBlocks, b5);
		Vector512<ulong> c6 = Avx512F.PermuteVar8x64x2(b2, highBlocks, b6);
		Vector512<ulong> c7 = Avx512F.PermuteVar8x64x2(b3, highBlocks, b7);

		Avx512F.Shuffle4x128(c0, c1, 0b01_00_01_00).AsByte().StoreUnsafe(ref output);
		Avx512F.Shuffle4x128(c2, c3, 0b01_00_01_00).AsByte().StoreUnsafe(ref output, 64);
		Avx512F.Shuffle4x128(c0, c1, 0b11_10_11_10).AsByte().StoreUnsafe(ref output, 128);
		Avx512F.Shuffle4x128(c2, c3, 0b11_10_11_10).AsByte().StoreUnsafe(ref output, 192);
		Avx512F.Shuffle4x128(c4, c5, 0b01_00_01_00).AsByte().StoreUnsafe(ref output, 256);
		Avx512F.Shuffle4x128(c6, c7, 0b01_00_01_00).AsByte().StoreUnsafe(ref output, 320);
		Avx512F.Shuffle4x128(c4, c5, 0b11_10_11_10).AsByte().StoreUnsafe(ref output, 384);
		Avx512F.Shuffle4x128(c6, c7, 0b11_10_11_10).AsByte().StoreUnsafe(ref output, 448);
	}

	// Unrolled, so that every message word has a constant index and stays in a register; each rotation is a single instruction, so all fourteen steps still inline.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds
	(
		ref Vector512<uint> v0, ref Vector512<uint> v1, ref Vector512<uint> v2, ref Vector512<uint> v3,
		ref Vector512<uint> v4, ref Vector512<uint> v5, ref Vector512<uint> v6, ref Vector512<uint> v7,
		ref Vector512<uint> v8, ref Vector512<uint> v9, ref Vector512<uint> v10, ref Vector512<uint> v11,
		ref Vector512<uint> v12, ref Vector512<uint> v13, ref Vector512<uint> v14, ref Vector512<uint> v15,
		ref Vector512<uint> message
	)
	{
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 0, 2, 4, 6, 1, 3, 5, 7);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 8, 10, 12, 14, 9, 11, 13, 15);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 2, 3, 7, 4, 6, 10, 0, 13);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 1, 12, 9, 15, 11, 5, 14, 8);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 3, 10, 13, 7, 4, 12, 2, 14);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 6, 9, 11, 8, 5, 0, 15, 1);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 10, 12, 14, 13, 7, 9, 3, 15);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 4, 11, 5, 1, 0, 2, 8, 6);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 12, 9, 15, 14, 13, 11, 10, 8);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 7, 5, 0, 6, 2, 3, 1, 4);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 9, 11, 8, 15, 14, 5, 12, 1);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 13, 0, 2, 4, 3, 10, 6, 7);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message, 11, 5, 1, 8, 15, 0, 9, 6);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref message, 14, 2, 3, 7, 10, 12, 4, 13);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step
	(
		ref Vector512<uint> a0, ref Vector512<uint> a1, ref Vector512<uint> a2, ref Vector512<uint> a3,
		ref Vector512<uint> b0, ref Vector512<uint> b1, ref Vector512<uint> b2, ref Vector512<uint> b3,
		ref Vector512<uint> c0, ref Vector512<uint> c1, ref Vector512<uint> c2, ref Vector512<uint> c3,
		ref Vector512<uint> d0, ref Vector512<uint> d1, ref Vector512<uint> d2, ref Vector512<uint> d3,
		ref Vector512<uint> message,
		int x0, int x1, int x2, int x3,
		int y0, int y1, int y2, int y3
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
		a0 = a0 + Unsafe.Add(ref message, y0) + b0;
		a1 = a1 + Unsafe.Add(ref message, y1) + b1;
		a2 = a2 + Unsafe.Add(ref message, y2) + b2;
		a3 = a3 + Unsafe.Add(ref message, y3) + b3;
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
