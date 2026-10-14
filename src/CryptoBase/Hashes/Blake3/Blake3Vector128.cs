using static CryptoBase.Hashes.Blake3.Blake3Constants;

namespace CryptoBase.Hashes.Blake3;

internal readonly partial struct Blake3Vector128 : IBlake3XofKernel
{
	public static bool IsSupported => Sse2.IsSupported || AdvSimd.Arm64.IsSupported;

	public static int Degree => 4;

	public static void HashChunks(ref byte input, nuint length, ref readonly uint key, ulong counter, uint flags, ref byte output)
	{
		for (; length > 4 * ChunkLength; length -= 4 * ChunkLength)
		{
			Hash(ref input, 4, 0, in key, counter, flags, ref output);
			input = ref Unsafe.Add(ref input, 4 * ChunkLength);
			output = ref Unsafe.Add(ref output, 4 * OutLength);
			counter += 4;
		}

		nuint count = length / ChunkLength;
		nuint tailLength = length % ChunkLength;

		// Next to a single full chunk, a partial one hashes faster on its own than in the lanes, except on ARM64 from fifteen blocks.
		if (count > 1 || count is 1 && AdvSimd.Arm64.IsSupported && tailLength > 14 * BlockLength)
		{
			HashLast(ref input, count, tailLength, in key, counter, flags, ref output);
			return;
		}

		if (count is 1)
		{
			Blake3Compressor.HashChunk(ref input, ChunkLength, in key, counter, flags, ref output);
		}

		if (tailLength is not 0)
		{
			Blake3Compressor.HashChunk(ref Unsafe.Add(ref input, count * ChunkLength), tailLength, in key, counter + count, flags, ref Unsafe.Add(ref output, count * OutLength));
		}
	}

	public static void HashParents(ref byte input, nuint count, ref readonly uint key, uint flags, ref byte output)
	{
		for (; count >= 4; count -= 4)
		{
			Hash(ref input, 4, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
			input = ref Unsafe.Add(ref input, 4 * BlockLength);
			output = ref Unsafe.Add(ref output, 4 * OutLength);
		}

		if (count > 1)
		{
			Hash(ref input, count, 0, in key, 0, flags | Blake3Flags.Parent, ref output);
		}
		else if (count is 1)
		{
			Blake3Compressor.Compress(in key, ref input, BlockLength, 0, flags | Blake3Flags.Parent, ref output);
		}
	}

	public static void XofMany(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		for (; count >= 4; count -= 4)
		{
			Xof(in cv, ref block, blockLength, counter, flags, 4, ref output);
			output = ref Unsafe.Add(ref output, 4 * BlockLength);
			counter += 4;
		}

		if (count > 1)
		{
			Xof(in cv, ref block, blockLength, counter, flags, count, ref output);
		}
		else if (count is 1)
		{
			Blake3Compressor.CompressXof(in cv, ref block, blockLength, counter, flags, ref output);
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

		Debug.Assert(count is > 1 and <= 4);
		Debug.Assert(tailBlocks < blockCount);

		// Lanes past count rehash the last input, which keeps every load inside the input.
		nuint lastOffset = (count - 1) * stride - (tailBlocks is 0 ? 0 : (blockCount - tailBlocks) * BlockLength);
		nuint offset1 = count > 2 ? stride : lastOffset;
		nuint offset2 = count > 3 ? 2 * stride : lastOffset;
		nuint offset3 = lastOffset;

		ref uint k = ref Unsafe.AsRef(in key);
		Vector128<uint> h0 = Vector128.Create(k);
		Vector128<uint> h1 = Vector128.Create(Unsafe.Add(ref k, 1));
		Vector128<uint> h2 = Vector128.Create(Unsafe.Add(ref k, 2));
		Vector128<uint> h3 = Vector128.Create(Unsafe.Add(ref k, 3));
		Vector128<uint> h4 = Vector128.Create(Unsafe.Add(ref k, 4));
		Vector128<uint> h5 = Vector128.Create(Unsafe.Add(ref k, 5));
		Vector128<uint> h6 = Vector128.Create(Unsafe.Add(ref k, 6));
		Vector128<uint> h7 = Vector128.Create(Unsafe.Add(ref k, 7));
		Vector128<uint> counterLow = Vector128.Create((uint)counter);

		if (chunks)
		{
			counterLow += Vector128<uint>.Indices;
		}

		Vector128<uint> counterHigh = Vector128.Create((uint)(counter >> 32)) - Vector128.LessThan(counterLow, Vector128.Create((uint)counter));
		Unsafe.SkipInit(out InlineArray16<Vector128<uint>> message);
		uint blockFlags = flags | startFlags;

		do
		{
			LoadMessage(ref input, offset1, offset2, offset3, ref message[0]);
			Vector128<uint> laneFlags = Vector128.Create(blockCount is 1 ? blockFlags | endFlags : blockFlags);

			if (blockCount <= tailBlocks)
			{
				Vector128<uint> tail = Vector128.GreaterThanOrEqual(Vector128<uint>.Indices, Vector128.Create((uint)count - 1));
				uint tailFlags = flags;

				if (blockCount == tailBlocks)
				{
					h0 = Vector128.ConditionalSelect(tail, Vector128.Create(k), h0);
					h1 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 1)), h1);
					h2 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 2)), h2);
					h3 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 3)), h3);
					h4 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 4)), h4);
					h5 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 5)), h5);
					h6 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 6)), h6);
					h7 = Vector128.ConditionalSelect(tail, Vector128.Create(Unsafe.Add(ref k, 7)), h7);
					tailFlags |= startFlags;
				}

				laneFlags = Vector128.ConditionalSelect(tail, Vector128.Create(tailFlags), laneFlags);
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
			Vector128<uint> v12 = counterLow;
			Vector128<uint> v13 = counterHigh;
			Vector128<uint> v14 = Vector128.Create((uint)BlockLength);
			Vector128<uint> v15 = laneFlags;

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

		VectorTranspose.Transpose(ref h0, ref h1, ref h2, ref h3);
		VectorTranspose.Transpose(ref h4, ref h5, ref h6, ref h7);

		h0.AsByte().StoreUnsafe(ref output);
		h4.AsByte().StoreUnsafe(ref output, 16);
		h1.AsByte().StoreUnsafe(ref output, 32);
		h5.AsByte().StoreUnsafe(ref output, 48);

		if (count > 2)
		{
			h2.AsByte().StoreUnsafe(ref output, 64);
			h6.AsByte().StoreUnsafe(ref output, 80);
		}

		if (count > 3)
		{
			h3.AsByte().StoreUnsafe(ref output, 96);
			h7.AsByte().StoreUnsafe(ref output, 112);
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void Xof(ref readonly uint cv, ref byte block, uint blockLength, ulong counter, uint flags, nuint count, ref byte output)
	{
		Debug.Assert(count is > 1 and <= 4);

		Unsafe.SkipInit(out InlineArray16<Vector128<uint>> message);

		for (int i = 0; i < 16; ++i)
		{
			message[i] = Vector128.Create(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref block, i * sizeof(uint))));
		}

		ref uint h = ref Unsafe.AsRef(in cv);
		Vector128<uint> v0 = Vector128.Create(h);
		Vector128<uint> v1 = Vector128.Create(Unsafe.Add(ref h, 1));
		Vector128<uint> v2 = Vector128.Create(Unsafe.Add(ref h, 2));
		Vector128<uint> v3 = Vector128.Create(Unsafe.Add(ref h, 3));
		Vector128<uint> v4 = Vector128.Create(Unsafe.Add(ref h, 4));
		Vector128<uint> v5 = Vector128.Create(Unsafe.Add(ref h, 5));
		Vector128<uint> v6 = Vector128.Create(Unsafe.Add(ref h, 6));
		Vector128<uint> v7 = Vector128.Create(Unsafe.Add(ref h, 7));
		Vector128<uint> v8 = Vector128.Create(IV0);
		Vector128<uint> v9 = Vector128.Create(IV1);
		Vector128<uint> v10 = Vector128.Create(IV2);
		Vector128<uint> v11 = Vector128.Create(IV3);
		Vector128<uint> v12 = Vector128.Create((uint)counter) + Vector128<uint>.Indices;
		Vector128<uint> v13 = Vector128.Create((uint)(counter >> 32)) - Vector128.LessThan(v12, Vector128.Create((uint)counter));
		Vector128<uint> v14 = Vector128.Create(blockLength);
		Vector128<uint> v15 = Vector128.Create(flags);

		Rounds(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref v8, ref v9, ref v10, ref v11, ref v12, ref v13, ref v14, ref v15, ref message[0]);

		Vector128<uint> o0 = v0 ^ v8;
		Vector128<uint> o1 = v1 ^ v9;
		Vector128<uint> o2 = v2 ^ v10;
		Vector128<uint> o3 = v3 ^ v11;
		Vector128<uint> o4 = v4 ^ v12;
		Vector128<uint> o5 = v5 ^ v13;
		Vector128<uint> o6 = v6 ^ v14;
		Vector128<uint> o7 = v7 ^ v15;
		Vector128<uint> o8 = v8 ^ Vector128.Create(h);
		Vector128<uint> o9 = v9 ^ Vector128.Create(Unsafe.Add(ref h, 1));
		Vector128<uint> o10 = v10 ^ Vector128.Create(Unsafe.Add(ref h, 2));
		Vector128<uint> o11 = v11 ^ Vector128.Create(Unsafe.Add(ref h, 3));
		Vector128<uint> o12 = v12 ^ Vector128.Create(Unsafe.Add(ref h, 4));
		Vector128<uint> o13 = v13 ^ Vector128.Create(Unsafe.Add(ref h, 5));
		Vector128<uint> o14 = v14 ^ Vector128.Create(Unsafe.Add(ref h, 6));
		Vector128<uint> o15 = v15 ^ Vector128.Create(Unsafe.Add(ref h, 7));

		VectorTranspose.Transpose(ref o0, ref o1, ref o2, ref o3);
		VectorTranspose.Transpose(ref o4, ref o5, ref o6, ref o7);
		VectorTranspose.Transpose(ref o8, ref o9, ref o10, ref o11);
		VectorTranspose.Transpose(ref o12, ref o13, ref o14, ref o15);

		StoreBlock(o0, o4, o8, o12, ref output);
		StoreBlock(o1, o5, o9, o13, ref Unsafe.Add(ref output, BlockLength));

		if (count > 2)
		{
			StoreBlock(o2, o6, o10, o14, ref Unsafe.Add(ref output, 2 * BlockLength));
		}

		if (count > 3)
		{
			StoreBlock(o3, o7, o11, o15, ref Unsafe.Add(ref output, 3 * BlockLength));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void LoadMessage(ref byte block, nuint offset1, nuint offset2, nuint offset3, ref Vector128<uint> message)
	{
		for (nuint i = 0; i < 16; i += 4)
		{
			Vector128<uint> m0 = Vector128.LoadUnsafe(ref block, i * sizeof(uint)).AsUInt32();
			Vector128<uint> m1 = Vector128.LoadUnsafe(ref block, offset1 + i * sizeof(uint)).AsUInt32();
			Vector128<uint> m2 = Vector128.LoadUnsafe(ref block, offset2 + i * sizeof(uint)).AsUInt32();
			Vector128<uint> m3 = Vector128.LoadUnsafe(ref block, offset3 + i * sizeof(uint)).AsUInt32();
			VectorTranspose.Transpose(ref m0, ref m1, ref m2, ref m3);
			Unsafe.Add(ref message, i) = m0;
			Unsafe.Add(ref message, i + 1) = m1;
			Unsafe.Add(ref message, i + 2) = m2;
			Unsafe.Add(ref message, i + 3) = m3;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreBlock(Vector128<uint> w0, Vector128<uint> w4, Vector128<uint> w8, Vector128<uint> w12, ref byte output)
	{
		w0.AsByte().StoreUnsafe(ref output);
		w4.AsByte().StoreUnsafe(ref output, 16);
		w8.AsByte().StoreUnsafe(ref output, 32);
		w12.AsByte().StoreUnsafe(ref output, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds
	(
		ref Vector128<uint> v0, ref Vector128<uint> v1, ref Vector128<uint> v2, ref Vector128<uint> v3,
		ref Vector128<uint> v4, ref Vector128<uint> v5, ref Vector128<uint> v6, ref Vector128<uint> v7,
		ref Vector128<uint> v8, ref Vector128<uint> v9, ref Vector128<uint> v10, ref Vector128<uint> v11,
		ref Vector128<uint> v12, ref Vector128<uint> v13, ref Vector128<uint> v14, ref Vector128<uint> v15,
		ref Vector128<uint> message
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
		ref Vector128<uint> v0, ref Vector128<uint> v1, ref Vector128<uint> v2, ref Vector128<uint> v3,
		ref Vector128<uint> v4, ref Vector128<uint> v5, ref Vector128<uint> v6, ref Vector128<uint> v7,
		ref Vector128<uint> v8, ref Vector128<uint> v9, ref Vector128<uint> v10, ref Vector128<uint> v11,
		ref Vector128<uint> v12, ref Vector128<uint> v13, ref Vector128<uint> v14, ref Vector128<uint> v15,
		ref Vector128<uint> message
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
		ref Vector128<uint> a0, ref Vector128<uint> a1, ref Vector128<uint> a2, ref Vector128<uint> a3,
		ref Vector128<uint> b0, ref Vector128<uint> b1, ref Vector128<uint> b2, ref Vector128<uint> b3,
		ref Vector128<uint> c0, ref Vector128<uint> c1, ref Vector128<uint> c2, ref Vector128<uint> c3,
		ref Vector128<uint> d0, ref Vector128<uint> d1, ref Vector128<uint> d2, ref Vector128<uint> d3,
		ref Vector128<uint> message,
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
	private static Vector128<uint> Word(ref Vector128<uint> message, ref byte words, int i)
	{
		return Unsafe.Add(ref message, Unsafe.Add(ref words, i));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step
	(
		ref Vector128<uint> a0, ref Vector128<uint> a1, ref Vector128<uint> a2, ref Vector128<uint> a3,
		ref Vector128<uint> b0, ref Vector128<uint> b1, ref Vector128<uint> b2, ref Vector128<uint> b3,
		ref Vector128<uint> c0, ref Vector128<uint> c1, ref Vector128<uint> c2, ref Vector128<uint> c3,
		ref Vector128<uint> d0, ref Vector128<uint> d1, ref Vector128<uint> d2, ref Vector128<uint> d3,
		ref Vector128<uint> message, ref byte words
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
