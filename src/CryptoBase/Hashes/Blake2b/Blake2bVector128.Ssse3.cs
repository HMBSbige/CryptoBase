using static CryptoBase.Hashes.Blake2b.Blake2bCore;
using static CryptoBase.Hashes.Blake2b.Blake2bMessageSchedule;

namespace CryptoBase.Hashes.Blake2b;

internal readonly partial struct Blake2bVector128
{
	// Constant message indices avoid constructing and rereading a per-block schedule.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void CompressSsse3(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag)
	{
		ref byte block = ref MemoryMarshal.GetReference(blocks);
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

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			Vector128<ulong> rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			Vector128<ulong> rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			Vector128<ulong> rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			Vector128<ulong> rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 5, 1, 0, 11, 3, 12, 2, 7);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 11, 12, 5, 15, 8, 0, 2, 13);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 9, 10, 3, 7, 4, 14, 6, 1);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 7, 3, 13, 11, 9, 1, 12, 14);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 15, 2, 5, 4, 8, 6, 10, 0);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 9, 5, 2, 10, 0, 7, 4, 15);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 3, 14, 11, 6, 13, 1, 12, 8);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 2, 6, 0, 8, 12, 10, 11, 3);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 1, 4, 7, 15, 9, 13, 5, 14);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 12, 1, 14, 4, 5, 15, 13, 10);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 8, 0, 6, 9, 11, 7, 3, 2);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 13, 7, 12, 3, 11, 14, 1, 9);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 2, 5, 15, 8, 10, 0, 4, 6);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 6, 14, 11, 0, 15, 9, 3, 8);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 10, 12, 13, 1, 5, 2, 7, 4);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 10, 8, 7, 1, 2, 4, 6, 5);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 13, 15, 9, 3, 0, 11, 14, 12);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

			StepSsse3(ref a0, ref a1, ref b0, ref b1, ref c0, ref c1, ref d0, ref d1, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			rotatedA0 = Sse2.Shuffle(a1.AsDouble(), a0.AsDouble(), 0b01).AsUInt64();
			rotatedA1 = Sse2.Shuffle(a0.AsDouble(), a1.AsDouble(), 0b01).AsUInt64();
			rotatedC0 = Sse2.Shuffle(c0.AsDouble(), c1.AsDouble(), 0b01).AsUInt64();
			rotatedC1 = Sse2.Shuffle(c1.AsDouble(), c0.AsDouble(), 0b01).AsUInt64();
			StepSsse3(ref rotatedA0, ref rotatedA1, ref b0, ref b1, ref rotatedC0, ref rotatedC1, ref d1, ref d0, ref block, 5, 1, 0, 11, 3, 12, 2, 7);
			a0 = Sse2.Shuffle(rotatedA0.AsDouble(), rotatedA1.AsDouble(), 0b01).AsUInt64();
			a1 = Sse2.Shuffle(rotatedA1.AsDouble(), rotatedA0.AsDouble(), 0b01).AsUInt64();
			c0 = Sse2.Shuffle(rotatedC1.AsDouble(), rotatedC0.AsDouble(), 0b01).AsUInt64();
			c1 = Sse2.Shuffle(rotatedC0.AsDouble(), rotatedC1.AsDouble(), 0b01).AsUInt64();

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
	private static void StepSsse3(ref Vector128<ulong> a0, ref Vector128<ulong> a1, ref Vector128<ulong> b0, ref Vector128<ulong> b1, ref Vector128<ulong> c0, ref Vector128<ulong> c1, ref Vector128<ulong> d0, ref Vector128<ulong> d1, ref byte block, int x0, int x1, int x2, int x3, int y0, int y1, int y2, int y3)
	{
		a0 = a0 + LoadPair(ref block, x0, x1) + b0;
		a1 = a1 + LoadPair(ref block, x2, x3) + b1;
		d0 = Sse2.Shuffle((d0 ^ a0).AsUInt32(), 0b10_11_00_01).AsUInt64();
		d1 = Sse2.Shuffle((d1 ^ a1).AsUInt32(), 0b10_11_00_01).AsUInt64();
		c0 += d0;
		c1 += d1;
		b0 = Ssse3.Shuffle((b0 ^ c0).AsByte(), Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)).AsUInt64();
		b1 = Ssse3.Shuffle((b1 ^ c1).AsByte(), Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)).AsUInt64();
		a0 = a0 + LoadPair(ref block, y0, y1) + b0;
		a1 = a1 + LoadPair(ref block, y2, y3) + b1;
		d0 = Ssse3.Shuffle((d0 ^ a0).AsByte(), Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)).AsUInt64();
		d1 = Ssse3.Shuffle((d1 ^ a1).AsByte(), Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)).AsUInt64();
		c0 += d0;
		c1 += d1;
		// As in G, XOR both halves before rotating either; the interleaved form is slower on 32-bit x86.
		b0 ^= c0;
		b1 ^= c1;
		b0 = b0 >>> 63 | b0 + b0;
		b1 = b1 >>> 63 | b1 + b1;
	}
}
