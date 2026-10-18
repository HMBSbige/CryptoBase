using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal readonly struct Blake3Scalar : IBlake3Compressor, IBlake3XofKernel
{
	public static bool IsSupported => true;

	public static int Degree => 1;

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void CompressBlocks(ref uint cv, ref byte blocks, nuint blockCount, ulong counter, uint flags, uint startFlags, uint endFlags)
	{
		Debug.Assert(blockCount is not 0);

		uint h0 = cv;
		uint h1 = Unsafe.Add(ref cv, 1);
		uint h2 = Unsafe.Add(ref cv, 2);
		uint h3 = Unsafe.Add(ref cv, 3);
		uint h4 = Unsafe.Add(ref cv, 4);
		uint h5 = Unsafe.Add(ref cv, 5);
		uint h6 = Unsafe.Add(ref cv, 6);
		uint h7 = Unsafe.Add(ref cv, 7);
		uint blockFlags = flags | startFlags;

		do
		{
			uint v0 = h0;
			uint v1 = h1;
			uint v2 = h2;
			uint v3 = h3;
			uint v4 = h4;
			uint v5 = h5;
			uint v6 = h6;
			uint v7 = h7;
			uint v8 = IV0;
			uint v9 = IV1;
			uint v10 = IV2;
			uint v11 = IV3;
			uint v12 = (uint)counter;
			uint v13 = (uint)(counter >> 32);
			uint v14 = BlockLength;
			uint v15 = blockCount is 1 ? blockFlags | endFlags : blockFlags;

			Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref blocks);

			h0 = v0 ^ v8;
			h1 = v1 ^ v9;
			h2 = v2 ^ v10;
			h3 = v3 ^ v11;
			h4 = v4 ^ v12;
			h5 = v5 ^ v13;
			h6 = v6 ^ v14;
			h7 = v7 ^ v15;

			blockFlags = flags;
			blocks = ref Unsafe.Add(ref blocks, BlockLength);
		} while (--blockCount is not 0);

		cv = h0;
		Unsafe.Add(ref cv, 1) = h1;
		Unsafe.Add(ref cv, 2) = h2;
		Unsafe.Add(ref cv, 3) = h3;
		Unsafe.Add(ref cv, 4) = h4;
		Unsafe.Add(ref cv, 5) = h5;
		Unsafe.Add(ref cv, 6) = h6;
		Unsafe.Add(ref cv, 7) = h7;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Compress(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		ref uint h = ref Unsafe.AsRef(in cv);
		uint v0 = h;
		uint v1 = Unsafe.Add(ref h, 1);
		uint v2 = Unsafe.Add(ref h, 2);
		uint v3 = Unsafe.Add(ref h, 3);
		uint v4 = Unsafe.Add(ref h, 4);
		uint v5 = Unsafe.Add(ref h, 5);
		uint v6 = Unsafe.Add(ref h, 6);
		uint v7 = Unsafe.Add(ref h, 7);
		uint v8 = IV0;
		uint v9 = IV1;
		uint v10 = IV2;
		uint v11 = IV3;
		uint v12 = (uint)counter;
		uint v13 = (uint)(counter >> 32);
		uint v14 = blockLength;
		uint v15 = flags;

		Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block);

		WriteWord(ref output, 0, v0 ^ v8);
		WriteWord(ref output, 1, v1 ^ v9);
		WriteWord(ref output, 2, v2 ^ v10);
		WriteWord(ref output, 3, v3 ^ v11);
		WriteWord(ref output, 4, v4 ^ v12);
		WriteWord(ref output, 5, v5 ^ v13);
		WriteWord(ref output, 6, v6 ^ v14);
		WriteWord(ref output, 7, v7 ^ v15);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void CompressXof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, ref byte output)
	{
		ref uint h = ref Unsafe.AsRef(in cv);
		uint v0 = h;
		uint v1 = Unsafe.Add(ref h, 1);
		uint v2 = Unsafe.Add(ref h, 2);
		uint v3 = Unsafe.Add(ref h, 3);
		uint v4 = Unsafe.Add(ref h, 4);
		uint v5 = Unsafe.Add(ref h, 5);
		uint v6 = Unsafe.Add(ref h, 6);
		uint v7 = Unsafe.Add(ref h, 7);
		uint v8 = IV0;
		uint v9 = IV1;
		uint v10 = IV2;
		uint v11 = IV3;
		uint v12 = (uint)counter;
		uint v13 = (uint)(counter >> 32);
		uint v14 = blockLength;
		uint v15 = flags;

		Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block);

		WriteWord(ref output, 0, v0 ^ v8);
		WriteWord(ref output, 1, v1 ^ v9);
		WriteWord(ref output, 2, v2 ^ v10);
		WriteWord(ref output, 3, v3 ^ v11);
		WriteWord(ref output, 4, v4 ^ v12);
		WriteWord(ref output, 5, v5 ^ v13);
		WriteWord(ref output, 6, v6 ^ v14);
		WriteWord(ref output, 7, v7 ^ v15);
		WriteWord(ref output, 8, v8 ^ h);
		WriteWord(ref output, 9, v9 ^ Unsafe.Add(ref h, 1));
		WriteWord(ref output, 10, v10 ^ Unsafe.Add(ref h, 2));
		WriteWord(ref output, 11, v11 ^ Unsafe.Add(ref h, 3));
		WriteWord(ref output, 12, v12 ^ Unsafe.Add(ref h, 4));
		WriteWord(ref output, 13, v13 ^ Unsafe.Add(ref h, 5));
		WriteWord(ref output, 14, v14 ^ Unsafe.Add(ref h, 6));
		WriteWord(ref output, 15, v15 ^ Unsafe.Add(ref h, 7));
	}

	[SkipLocalsInit]
	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length >= ChunkLength; length -= ChunkLength)
		{
			InlineArray8<uint> cv = Blake3Words.Copy(in key);
			CompressBlocks(ref cv[0], ref input, ChunkBlocks, counter, flags, Blake3Flags.ChunkStart, Blake3Flags.ChunkEnd);
			Blake3Words.Store(ref output, in cv);
			input = ref Unsafe.Add(ref input, ChunkLength);
			output = ref Unsafe.Add(ref output, OutLength);
			++counter;
		}

		if (length is not 0)
		{
			Blake3Compressor.HashChunk(ref input, length, in key, counter, flags, ref output);
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		for (nuint i = 0; i < count; ++i)
		{
			Compress(in key, ref Unsafe.Add(ref input, i * BlockLength), BlockLength, 0, flags | Blake3Flags.Parent, ref Unsafe.Add(ref output, i * OutLength));
		}
	}

	public static void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		for (nuint i = 0; i < count; ++i)
		{
			CompressXof(in cv, ref block, blockLength, counter + i, flags, ref Unsafe.Add(ref output, i * BlockLength));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds
	(
		ref uint v0, ref uint v1, ref uint v2, ref uint v3,
		ref uint v4, ref uint v5, ref uint v6, ref uint v7,
		ref uint v8, ref uint v9, ref uint v10, ref uint v11,
		ref uint v12, ref uint v13, ref uint v14, ref uint v15,
		ref byte block
	)
	{
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 8, 10, 12, 14, 9, 11, 13, 15);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 2, 3, 7, 4, 6, 10, 0, 13);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 1, 12, 9, 15, 11, 5, 14, 8);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 3, 10, 13, 7, 4, 12, 2, 14);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 6, 9, 11, 8, 5, 0, 15, 1);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 10, 12, 14, 13, 7, 9, 3, 15);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 4, 11, 5, 1, 0, 2, 8, 6);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 12, 9, 15, 14, 13, 11, 10, 8);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 7, 5, 0, 6, 2, 3, 1, 4);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 9, 11, 8, 15, 14, 5, 12, 1);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 13, 0, 2, 4, 3, 10, 6, 7);
		Step(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref block, 11, 5, 1, 8, 15, 0, 9, 6);
		Step(ref v0, ref v1, ref v2, ref v3, ref v5, ref v6, ref v7, ref v4, ref v10, ref v11, ref v8, ref v9, ref v15, ref v12, ref v13, ref v14, ref block, 14, 2, 3, 7, 10, 12, 4, 13);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step
	(
		ref uint a0, ref uint a1, ref uint a2, ref uint a3,
		ref uint b0, ref uint b1, ref uint b2, ref uint b3,
		ref uint c0, ref uint c1, ref uint c2, ref uint c3,
		ref uint d0, ref uint d1, ref uint d2, ref uint d3,
		ref byte block,
		int x0, int x1, int x2, int x3,
		int y0, int y1, int y2, int y3
	)
	{
		// Adding the message word first keeps one addition off the b dependency chain.
		a0 = a0 + MessageWord(ref block, x0) + b0;
		a1 = a1 + MessageWord(ref block, x1) + b1;
		a2 = a2 + MessageWord(ref block, x2) + b2;
		a3 = a3 + MessageWord(ref block, x3) + b3;
		d0 = BitOperations.RotateRight(d0 ^ a0, 16);
		d1 = BitOperations.RotateRight(d1 ^ a1, 16);
		d2 = BitOperations.RotateRight(d2 ^ a2, 16);
		d3 = BitOperations.RotateRight(d3 ^ a3, 16);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = BitOperations.RotateRight(b0 ^ c0, 12);
		b1 = BitOperations.RotateRight(b1 ^ c1, 12);
		b2 = BitOperations.RotateRight(b2 ^ c2, 12);
		b3 = BitOperations.RotateRight(b3 ^ c3, 12);
		a0 = a0 + MessageWord(ref block, y0) + b0;
		a1 = a1 + MessageWord(ref block, y1) + b1;
		a2 = a2 + MessageWord(ref block, y2) + b2;
		a3 = a3 + MessageWord(ref block, y3) + b3;
		d0 = BitOperations.RotateRight(d0 ^ a0, 8);
		d1 = BitOperations.RotateRight(d1 ^ a1, 8);
		d2 = BitOperations.RotateRight(d2 ^ a2, 8);
		d3 = BitOperations.RotateRight(d3 ^ a3, 8);
		c0 += d0;
		c1 += d1;
		c2 += d2;
		c3 += d3;
		b0 = BitOperations.RotateRight(b0 ^ c0, 7);
		b1 = BitOperations.RotateRight(b1 ^ c1, 7);
		b2 = BitOperations.RotateRight(b2 ^ c2, 7);
		b3 = BitOperations.RotateRight(b3 ^ c3, 7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint MessageWord(ref byte block, int index)
	{
		return Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, index * sizeof(uint)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteWord(ref byte destination, int index, uint value)
	{
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, index * sizeof(uint)), value);
	}
}
