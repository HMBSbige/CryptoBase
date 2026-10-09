using static CryptoBase.Hashes.Blake2b.Blake2bCore;

namespace CryptoBase.Hashes.Blake2b;

internal readonly partial struct Blake2bVector128 : IBlake2bKernel
{
	public static bool IsSupported => Sse2.IsSupported;

	// BLAKE2b σ in load order (column x, column y, diagonal x, diagonal y); diagonal lanes start at the fourth G to match the rotated rows.
	private static ReadOnlySpan<byte> Indices =>
	[
		0, 2, 4, 6, 1, 3, 5, 7,
		14, 8, 10, 12, 15, 9, 11, 13,
		14, 4, 9, 13, 10, 8, 15, 6,
		5, 1, 0, 11, 3, 12, 2, 7,
		11, 12, 5, 15, 8, 0, 2, 13,
		9, 10, 3, 7, 4, 14, 6, 1,
		7, 3, 13, 11, 9, 1, 12, 14,
		15, 2, 5, 4, 8, 6, 10, 0,
		9, 5, 2, 10, 0, 7, 4, 15,
		3, 14, 11, 6, 13, 1, 12, 8,
		2, 6, 0, 8, 12, 10, 11, 3,
		1, 4, 7, 15, 9, 13, 5, 14,
		12, 1, 14, 4, 5, 15, 13, 10,
		8, 0, 6, 9, 11, 7, 3, 2,
		13, 7, 12, 3, 11, 14, 1, 9,
		2, 5, 15, 8, 10, 0, 4, 6,
		6, 14, 11, 0, 15, 9, 3, 8,
		10, 12, 13, 1, 5, 2, 7, 4,
		10, 8, 7, 1, 2, 4, 6, 5,
		13, 15, 9, 3, 0, 11, 14, 12,
		0, 2, 4, 6, 1, 3, 5, 7,
		14, 8, 10, 12, 15, 9, 11, 13,
		14, 4, 9, 13, 10, 8, 15, 6,
		5, 1, 0, 11, 3, 12, 2, 7,
	];

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Compress(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(!blocks.IsEmpty && blocks.Length % BlockSizeInBytes is 0);

		if (Ssse3.IsSupported)
		{
			CompressSsse3(ref state, blocks, counter, finalFlag);
			return;
		}

		ref byte block = ref blocks.GetReference();
		nuint remainingBlocks = (uint)blocks.Length / BlockSizeInBytes;
		ulong counterLow = (ulong)counter;
		ulong counterHigh = (ulong)(counter >> 64);
		Vector128<ulong> h0 = Vector128.LoadUnsafe(ref state);
		Vector128<ulong> h1 = Vector128.LoadUnsafe(ref state, 2);
		Vector128<ulong> h2 = Vector128.LoadUnsafe(ref state, 4);
		Vector128<ulong> h3 = Vector128.LoadUnsafe(ref state, 6);
		Vector128<ulong> flags = Vector128.CreateUInt64(IV6 ^ finalFlag, IV7);

		do
		{
			Vector128<ulong> a0 = h0;
			Vector128<ulong> a1 = h1;
			Vector128<ulong> b0 = h2;
			Vector128<ulong> b1 = h3;
			Vector128<ulong> c0 = Vector128.Create(IV0, IV1);
			Vector128<ulong> c1 = Vector128.Create(IV2, IV3);
			Vector128<ulong> d0 = Vector128.CreateUInt64(IV4 ^ counterLow, IV5 ^ counterHigh);
			Vector128<ulong> d1 = flags;
			ref byte indices = ref MemoryMarshal.GetReference(Indices);

			for (int round = 0; round < Rounds; ++round)
			{
				Vector128<ulong> x0 = LoadMessagePair(ref block, indices, Unsafe.Add(ref indices, 1));
				Vector128<ulong> x1 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 2), Unsafe.Add(ref indices, 3));
				Vector128<ulong> y0 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 4), Unsafe.Add(ref indices, 5));
				Vector128<ulong> y1 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 6), Unsafe.Add(ref indices, 7));
				G(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, x0, x1, y0, y1);

				Vector128<ulong> rotatedA0 = Concat(a1, a0);
				Vector128<ulong> rotatedA1 = Concat(a0, a1);
				Vector128<ulong> rotatedC0 = Concat(c0, c1);
				Vector128<ulong> rotatedC1 = Concat(c1, c0);

				x0 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 8), Unsafe.Add(ref indices, 9));
				x1 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 10), Unsafe.Add(ref indices, 11));
				y0 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 12), Unsafe.Add(ref indices, 13));
				y1 = LoadMessagePair(ref block, Unsafe.Add(ref indices, 14), Unsafe.Add(ref indices, 15));

				G(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, x0, x1, y0, y1);

				a0 = Concat(rotatedA0, rotatedA1);
				a1 = Concat(rotatedA1, rotatedA0);
				c0 = Concat(rotatedC1, rotatedC0);
				c1 = Concat(rotatedC0, rotatedC1);
				indices = ref Unsafe.Add(ref indices, 16);
			}

			h0 ^= a0 ^ c0;
			h1 ^= a1 ^ c1;
			h2 ^= b0 ^ d0;
			h3 ^= b1 ^ d1;

			counterLow += BlockSizeInBytes;
			counterHigh += counterLow < BlockSizeInBytes ? 1UL : 0UL;
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
		} while (--remainingBlocks is not 0);

		h0.StoreUnsafe(ref state);
		h1.StoreUnsafe(ref state, 2);
		h2.StoreUnsafe(ref state, 4);
		h3.StoreUnsafe(ref state, 6);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void G(ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1, ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1, Vector128<ulong> x0, Vector128<ulong> x1, Vector128<ulong> y0, Vector128<ulong> y1)
	{
		// XOR both halves before rotating either: with only eight XMM registers, 32-bit x86 spills more and runs markedly slower when they interleave.
		a0 = a0 + x0 + b0;
		a1 = a1 + x1 + b1;
		d0 ^= a0;
		d1 ^= a1;
		d0 = Sse2.Shuffle(d0.AsUInt32(), 0b10_11_00_01).AsUInt64();
		d1 = Sse2.Shuffle(d1.AsUInt32(), 0b10_11_00_01).AsUInt64();
		c0 += d0;
		c1 += d1;
		b0 ^= c0;
		b1 ^= c1;
		b0 = b0 >>> 24 | b0 << 40;
		b1 = b1 >>> 24 | b1 << 40;
		a0 = a0 + y0 + b0;
		a1 = a1 + y1 + b1;
		d0 ^= a0;
		d1 ^= a1;
		d0 = Sse2.ShuffleHigh(Sse2.ShuffleLow(d0.AsUInt16(), 0b00_11_10_01), 0b00_11_10_01).AsUInt64();
		d1 = Sse2.ShuffleHigh(Sse2.ShuffleLow(d1.AsUInt16(), 0b00_11_10_01), 0b00_11_10_01).AsUInt64();
		c0 += d0;
		c1 += d1;
		b0 ^= c0;
		b1 ^= c1;
		b0 = b0 >>> 63 | b0 << 1;
		b1 = b1 >>> 63 | b1 << 1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> Concat(Vector128<ulong> left, Vector128<ulong> right)
	{
		return Sse2.Shuffle(left.AsDouble(), right.AsDouble(), 0b01).AsUInt64();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> LoadMessagePair(ref byte block, nuint first, nuint second)
	{
		Vector128<ulong> left = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, first * sizeof(ulong))));
		Vector128<ulong> right = Vector128.CreateScalarUnsafe(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, second * sizeof(ulong))));
		return Sse2.UnpackLow(left, right);
	}
}
