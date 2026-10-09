using static CryptoBase.Hashes.Blake2b.Blake2bCore;
using static CryptoBase.Hashes.Blake2b.Blake2bMessageSchedule;

namespace CryptoBase.Hashes.Blake2b;

internal readonly struct Blake2bVector256 : IBlake2bKernel
{
	public static bool IsSupported => Avx2.IsSupported;

	// Under AVX-512, holding the block in zmm registers and selecting words with vpermt2q was no faster than these 256-bit steps.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Compress(ref ulong state, ReadOnlySpan<byte> blocks, UInt128 counter, ulong finalFlag)
	{
		Debug.Assert(IsSupported);
		Debug.Assert(!blocks.IsEmpty && blocks.Length % BlockSizeInBytes is 0);

		ref byte block = ref MemoryMarshal.GetReference(blocks);
		nuint remainingBlocks = (uint)blocks.Length / BlockSizeInBytes;
		ulong counterLow = (ulong)counter;
		ulong counterHigh = (ulong)(counter >> 64);
		Vector256<ulong> h0 = Vector256.LoadUnsafe(ref state);
		Vector256<ulong> h1 = Vector256.LoadUnsafe(ref state, 4);

		do
		{
			Vector256<ulong> a = h0;
			Vector256<ulong> b = h1;
			Vector256<ulong> c = Vector256.Create(IV0, IV1, IV2, IV3);
			Vector256<ulong> d = Vector256.Create(IV4 ^ counterLow, IV5 ^ counterHigh, IV6 ^ finalFlag, IV7);

			Step(ref a, ref b, ref c, ref d, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 5, 1, 0, 11, 3, 12, 2, 7);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 11, 12, 5, 15, 8, 0, 2, 13);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 9, 10, 3, 7, 4, 14, 6, 1);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 7, 3, 13, 11, 9, 1, 12, 14);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 15, 2, 5, 4, 8, 6, 10, 0);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 9, 5, 2, 10, 0, 7, 4, 15);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 3, 14, 11, 6, 13, 1, 12, 8);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 2, 6, 0, 8, 12, 10, 11, 3);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 1, 4, 7, 15, 9, 13, 5, 14);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 12, 1, 14, 4, 5, 15, 13, 10);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 8, 0, 6, 9, 11, 7, 3, 2);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 13, 7, 12, 3, 11, 14, 1, 9);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 2, 5, 15, 8, 10, 0, 4, 6);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 6, 14, 11, 0, 15, 9, 3, 8);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 10, 12, 13, 1, 5, 2, 7, 4);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 10, 8, 7, 1, 2, 4, 6, 5);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 13, 15, 9, 3, 0, 11, 14, 12);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 0, 2, 4, 6, 1, 3, 5, 7);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 14, 8, 10, 12, 15, 9, 11, 13);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			Step(ref a, ref b, ref c, ref d, ref block, 14, 4, 9, 13, 10, 8, 15, 6);
			a = Avx2.Permute4x64(a, 0x93);
			c = Avx2.Permute4x64(c, 0x39);
			d = Avx2.Permute4x64(d, 0x4E);
			Step(ref a, ref b, ref c, ref d, ref block, 5, 1, 0, 11, 3, 12, 2, 7);
			a = Avx2.Permute4x64(a, 0x39);
			c = Avx2.Permute4x64(c, 0x93);
			d = Avx2.Permute4x64(d, 0x4E);

			h0 ^= a ^ c;
			h1 ^= b ^ d;

			counterLow += BlockSizeInBytes;
			counterHigh += counterLow < BlockSizeInBytes ? 1UL : 0UL;
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
		} while (--remainingBlocks is not 0);

		h0.StoreUnsafe(ref state);
		h1.StoreUnsafe(ref state, 4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Step(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d, ref byte block, int x0, int x1, int x2, int x3, int y0, int y1, int y2, int y3)
	{
		Vector256<ulong> x = Vector256.Create(LoadPair(ref block, x0, x1), LoadPair(ref block, x2, x3));
		a = a + x + b;

		if (Avx512F.VL.IsSupported)
		{
			d = Avx512F.VL.RotateRight(d ^ a, 32);
			c += d;
			b = Avx512F.VL.RotateRight(b ^ c, 24);
		}
		else
		{
			d = Avx2.Shuffle((d ^ a).AsUInt32(), 0b10_11_00_01).AsUInt64();
			c += d;
			b = Avx2.Shuffle((b ^ c).AsByte(), Vector256.Create(Vector128.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))).AsUInt64();
		}

		Vector256<ulong> y = Vector256.Create(LoadPair(ref block, y0, y1), LoadPair(ref block, y2, y3));
		a = a + y + b;

		if (Avx512F.VL.IsSupported)
		{
			d = Avx512F.VL.RotateRight(d ^ a, 16);
			c += d;
			b = Avx512F.VL.RotateRight(b ^ c, 63);
		}
		else
		{
			d = Avx2.Shuffle((d ^ a).AsByte(), Vector256.Create(Vector128.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))).AsUInt64();
			c += d;
			b ^= c;
			b = b >>> 63 | b + b;
		}
	}
}
